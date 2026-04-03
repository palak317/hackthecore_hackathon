import base64
import difflib
import json
import mimetypes
import os
import re
import tempfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, redirect, request, send_file, session, url_for
from flask_cors import CORS
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from pypdf import PdfReader
import requests
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer, pipeline

from steg_analyzer import analyze_image_for_steg

try:
    import pymysql
except ImportError:
    pymysql = None

try:
    from langdetect import detect as detect_language
except ImportError:  # pragma: no cover
    detect_language = None

try:
    from deep_translator import GoogleTranslator
except ImportError:  # pragma: no cover
    GoogleTranslator = None

try:
    from googletrans import Translator
except ImportError:  # pragma: no cover
    Translator = None


app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "gmail_phishguard_dev_key")
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LEGACY_FRONTEND_FILE = os.path.join(os.path.dirname(BASE_DIR), "phishguard", "index.html")
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
DEFAULT_CLIENT_SECRET_FILE = os.path.join(BASE_DIR, "client_secret.json")
LEGACY_CLIENT_SECRET_FILE = os.path.join(os.path.dirname(BASE_DIR), "phishguard", "client_secret.json")
CLIENT_SECRET_FILE = os.getenv(
    "GMAIL_CLIENT_SECRET",
    DEFAULT_CLIENT_SECRET_FILE if os.path.exists(DEFAULT_CLIENT_SECRET_FILE) else LEGACY_CLIENT_SECRET_FILE,
)
TOKEN_SIZE_LIMIT = 10 * 1024 * 1024
SUPPORTED_IMAGE_MIME_TYPES = {"image/jpeg", "image/jpg", "image/png"}
SUPPORTED_TEXT_MIME_TYPES = {"text/plain"}
PHISHING_THRESHOLD = 60
ANALYSIS_HISTORY: List[Dict[str, Any]] = []
DETAIL_CACHE: Dict[str, Dict[str, Any]] = {}
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "phishguard")
MYSQL_TABLE = os.getenv("MYSQL_TABLE", "threat_history")
LOCAL_TRANSLATION_MODEL = os.getenv("INDIC_TRANSLATION_MODEL", "Helsinki-NLP/opus-mt-mul-en")
TRANSLATION_CHUNK_SIZE = 600

# Allow OAuth callback over http://127.0.0.1 during local development only.
if os.getenv("FLASK_ENV") != "production":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

TEXT_SIGNALS: Dict[str, List[str]] = {
    "urgency": ["urgent", "immediately", "act now", "asap", "limited time", "now"],
    "fear": ["account blocked", "suspended", "locked", "disabled", "security alert", "terminated"],
    "authority": ["bank", "rbi", "support", "support team", "police", "cyber crime", "government officer"],
    "reward": ["won", "prize", "offer", "reward", "cashback", "lottery", "gift"],
    "sensitive_action": ["password", "otp", "verification code", "verify account", "login", "sign in", "pay now"],
}

# Add common Hindi and Marathi phishing phrases so the detector still works
# even when online translation is unavailable.
TEXT_SIGNALS["urgency"].extend(["तुरंत", "तात्काळ", "ताबडतोब", "लगेच", "आत्ताच", "अभी", "जल्दी"])
TEXT_SIGNALS["fear"].extend([
    "खाता बंद",
    "खाते बंद",
    "अकाउंट बंद",
    "ब्लॉक होईल",
    "ब्लॉक किया जाएगा",
    "बंद हो जाएगा",
    "निलंबित",
    "सस्पेंड",
])
TEXT_SIGNALS["authority"].extend([
    "बँक",
    "बैंक",
    "एसबीआय",
    "sbi",
    "आरबीआय",
    "पुलिस",
    "पोलीस",
    "सरकार",
    "अधिकारी",
    "सपोर्ट",
])
TEXT_SIGNALS["reward"].extend(["इनाम", "पुरस्कार", "ऑफर", "जिते", "जीता", "कॅशबॅक"])
TEXT_SIGNALS["sensitive_action"].extend([
    "ओटीपी",
    "otp",
    "पासवर्ड",
    "शेअर करा",
    "साझा करें",
    "लॉगिन",
    "सत्यापित",
    "व्हेरिफाय",
    "पडताळा",
])

KEYWORD_WEIGHTS = {
    "urgent": 12,
    "immediately": 14,
    "act now": 16,
    "account blocked": 18,
    "suspended": 18,
    "bank": 12,
    "support": 10,
    "police": 15,
    "won": 16,
    "prize": 16,
    "offer": 12,
    "password": 20,
    "otp": 22,
    "verification code": 20,
    "verify account": 18,
    "login": 18,
    "sbi": 15,
    "ओटीपी": 22,
    "पासवर्ड": 20,
    "शेअर करा": 18,
    "साझा करें": 18,
    "खाते बंद": 18,
    "खाता बंद": 18,
    "ब्लॉक होईल": 18,
    "बँक": 12,
    "बैंक": 12,
}

SUSPICIOUS_TLDS = {".xyz", ".ru", ".top", ".click", ".gq", ".tk", ".work", ".support", ".zip"}
URL_REGEX = re.compile(r"(https?://[^\s<>\"]+|www\.[^\s<>\"]+)", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_REGEX = re.compile(r"(?:(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?){2,4}\d{3,4})")
WORD_REGEX = re.compile(r"\b[\w'-]+\b")

PHISHING_TYPE_KEYWORDS = {
    "credential_theft": ["login", "password", "verify account", "sign in", "credentials", "पासवर्ड", "लॉगिन", "सत्यापित"],
    "otp_scam": ["otp", "one time password", "verification code", "passcode", "ओटीपी"],
    "reward_scam": ["prize", "offer", "reward", "gift", "lottery", "winner"],
    "impersonation": ["bank", "support", "police", "manager", "officer", "government", "बँक", "बैंक", "पुलिस", "पोलीस", "अधिकारी"],
}

BRAND_DOMAINS = {
    "hdfc": ["hdfcbank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "icici": ["icicibank.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "github": ["github.com"],
}

ROLE_PATTERNS = {
    "bank": ["bank manager", "account officer", "rbi officer"],
    "support": ["customer support", "technical team", "support executive"],
    "authority": ["police", "cyber crime", "government officer", "investigation officer"],
}
ROLE_PATTERNS["bank"].extend(["बँक मॅनेजर", "बैंक मैनेजर", "खाता अधिकारी", "अकाउंट ऑफिसर"])
ROLE_PATTERNS["support"].extend(["सपोर्ट टीम", "ग्राहक सहायता"])
ROLE_PATTERNS["authority"].extend(["पुलिस अधिकारी", "पोलीस अधिकारी", "सरकारी अधिकारी"])

ROLE_INTRO_PHRASES = ["i am", "this is", "speaking from", "calling from"]
ROLE_INTRO_PHRASES.extend(["मी", "मैं", "यह", "बोल रहा", "बोलत आहे", "कडून बोलत आहे"])

# This small offline translation map gives the UI an English fallback for the
# most common Hindi/Marathi phishing phrases when online translation fails.
LOCAL_TRANSLATION_MAP = {
    "नमस्कार": "Hello",
    "मी": "I",
    "बोलत आहे": "am speaking",
    "तुमचे": "your",
    "तुमचा": "your",
    "तुमच्या": "your",
    "खाते": "account",
    "खाता": "account",
    "बंद": "closed",
    "होण्याच्या": "about to be",
    "मार्गावर": "on the way",
    "आहे": "is",
    "कृपया": "please",
    "लगेच": "immediately",
    "ओटीपी": "OTP",
    "OTP": "OTP",
    "शेअर करा": "share",
    "नाहीतर": "otherwise",
    "ब्लॉक": "blocked",
    "केले": "made",
    "जाईल": "will be",
    "बँकेतून": "from the bank",
    "बैंक": "bank",
    "बँक": "bank",
    "एसबीआय": "SBI",
    "SBI": "SBI",
}
TRUSTED_BRANDS = list(BRAND_DOMAINS.keys())
TARGETING_KEYWORDS = {
    "financial": ["bank", "credit card", "account", "transaction", "loan", "upi", "refund"],
    "job": ["job", "internship", "resume", "hiring", "offer letter", "recruitment"],
    "shopping": ["order", "discount", "offer", "coupon", "delivery", "sale", "amazon"],
}
LOCATION_ALIASES = {
    "usa": "United States",
    "us": "United States",
    "india": "India",
    "russia": "Russia",
    "uk": "United Kingdom",
    "united kingdom": "United Kingdom",
    "singapore": "Singapore",
    "uae": "United Arab Emirates",
    "dubai": "United Arab Emirates",
}
TLD_LOCATION_MAP = {
    ".ru": "Russia",
    ".in": "India",
    ".uk": "United Kingdom",
    ".co.uk": "United Kingdom",
    ".us": "United States",
    ".xyz": "Unknown",
    ".ae": "United Arab Emirates",
    ".sg": "Singapore",
}


print("Loading phishing classifier...")
try:
    classifier = pipeline(
        "text-classification",
        model="mrm8488/bert-tiny-finetuned-sms-spam-detection",
    )
    print("Phishing classifier ready.")
except Exception as exc:
    print(f"Falling back to default text-classification pipeline: {exc}")
    classifier = pipeline("text-classification")

local_translation_pipeline = None
local_translation_status = "not_loaded"


def get_gmail_credentials() -> Credentials:
    if "credentials" not in session:
        raise PermissionError("Gmail authentication required")

    creds = Credentials(**session["credentials"])
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        session["credentials"] = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
        }
    return creds


def analyze_with_nlp(text_content: str) -> Dict[str, Any]:
    if not text_content or not text_content.strip():
        return {"label": "SAFE", "score": 0, "reason": "No text content"}

    result = classifier(text_content[:512])[0]
    label = result.get("label", "LABEL_0")
    confidence = float(result.get("score", 0.0))
    is_phishing = label == "LABEL_1"

    risk_score = confidence * 100.0 if is_phishing else (1.0 - confidence) * 100.0
    return {
        "label": "PHISHING" if is_phishing else "SAFE",
        "score": max(0, min(100, int(round(risk_score)))),
        "reason": "ML model found suspicious phishing language patterns" if is_phishing else "ML model did not see strong phishing intent",
    }


def detect_language_heuristic(text: str) -> str:
    """Fallback language detector when the dedicated library is unavailable."""
    if not text.strip():
        return "en"
    if re.search(r"[\u0900-\u097F]", text):
        return "hi"
    if re.search(r"[\u0600-\u06FF]", text):
        return "ar"
    if re.search(r"[\u4E00-\u9FFF]", text):
        return "zh"
    return "en"


def local_translate_to_english(text: str) -> str:
    """Translate common scam phrases locally when network translators fail."""
    translated = text or ""
    for source, target in sorted(LOCAL_TRANSLATION_MAP.items(), key=lambda item: len(item[0]), reverse=True):
        translated = translated.replace(source, target)

    translated = re.sub(r"\s+", " ", translated).strip()
    return translated


def get_local_translation_pipeline() -> Optional[Any]:
    """Load a cached Hugging Face translation model for Indic-to-English translation."""
    global local_translation_pipeline, local_translation_status

    if local_translation_pipeline is not None:
        return local_translation_pipeline
    if local_translation_status == "unavailable":
        return None

    try:
        tokenizer = AutoTokenizer.from_pretrained(LOCAL_TRANSLATION_MODEL, local_files_only=True)
        model = AutoModelForSeq2SeqLM.from_pretrained(LOCAL_TRANSLATION_MODEL, local_files_only=True)
        local_translation_pipeline = pipeline(
            "translation",
            model=model,
            tokenizer=tokenizer,
        )
        local_translation_status = LOCAL_TRANSLATION_MODEL
    except Exception:
        local_translation_pipeline = None
        local_translation_status = "unavailable"

    return local_translation_pipeline


def split_translation_chunks(text: str, max_chars: int = TRANSLATION_CHUNK_SIZE) -> List[str]:
    """Split long text into smaller pieces so local translation models stay stable."""
    cleaned = (text or "").strip()
    if not cleaned:
        return []

    chunks: List[str] = []
    current = ""
    for part in re.split(r"(?<=[.!?\n])\s+", cleaned):
        if not part:
            continue
        candidate = f"{current} {part}".strip() if current else part
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            chunks.append(current)
        current = part

    if current:
        chunks.append(current)
    return chunks


def translate_with_local_model(text: str) -> str:
    """Translate text with a locally cached model before falling back to web translators."""
    translator_pipeline = get_local_translation_pipeline()
    if translator_pipeline is None:
        return ""

    translated_parts: List[str] = []
    for chunk in split_translation_chunks(text):
        try:
            result = translator_pipeline(chunk, max_length=512)
            translated = result[0].get("translation_text", "").strip() if result else ""
            if translated:
                translated_parts.append(translated)
        except Exception:
            return ""

    return "\n".join(part for part in translated_parts if part).strip()


def translate_to_english(text: str, detected_language: str) -> Tuple[str, str]:
    """Translate text to English before phishing analysis whenever possible."""
    if not text.strip() or detected_language == "en":
        return text, "original_text"

    local_model_translation = translate_with_local_model(text)
    if local_model_translation:
        return local_model_translation, local_translation_status

    if GoogleTranslator is not None:
        try:
            translated = GoogleTranslator(source="auto", target="en").translate(text)
            if translated and translated.strip():
                return translated, "deep_translator"
        except Exception:
            pass

    if Translator is not None:
        try:
            translated = Translator().translate(text, dest="en").text
            if translated and translated.strip():
                return translated, "googletrans"
        except Exception:
            pass

    local_translation = local_translate_to_english(text)
    if local_translation.strip() and local_translation.strip() != text.strip():
        return local_translation, "local_phrase_map"
    return text, "original_text"


def detect_and_translate_text(text: str) -> Dict[str, Any]:
    """Detect input language and create an English version for one analysis pipeline."""
    clean_text = text or ""
    if not clean_text.strip():
        return {
            "detected": "en",
            "translated_text": "",
            "original_text": "",
            "translation_applied": False,
            "translation_engine": "none",
        }

    try:
        detected = detect_language(clean_text) if detect_language is not None else detect_language_heuristic(clean_text)
    except Exception:
        detected = detect_language_heuristic(clean_text)

    translated_text, translation_engine = translate_to_english(clean_text, detected)
    return {
        "detected": detected,
        "translated_text": translated_text,
        "original_text": clean_text,
        "translation_applied": bool(clean_text.strip()) and translated_text.strip() != clean_text.strip(),
        "translation_engine": translation_engine,
    }


def extract_entities(text: str) -> Dict[str, List[str]]:
    """Extract URLs, emails, and phone numbers so they can be scored separately."""
    haystack = text or ""
    urls: List[str] = []
    for match in URL_REGEX.findall(haystack):
        normalized = match if match.lower().startswith(("http://", "https://")) else f"http://{match}"
        urls.append(normalized.rstrip(".,)"))
    phones = [match.strip() for match in PHONE_REGEX.findall(haystack) if len(re.sub(r"\D", "", match)) >= 8]
    return {
        "urls": list(dict.fromkeys(urls)),
        "emails": list(dict.fromkeys(EMAIL_REGEX.findall(haystack))),
        "phones": list(dict.fromkeys(phones)),
    }


def analyze_text_features(text: str) -> Dict[str, Any]:
    lowered = (text or "").lower()
    words = WORD_REGEX.findall(lowered)
    total_words = max(1, len(words))

    detected_keywords: List[str] = []
    suspicious_phrases: List[str] = []
    category_hits: Dict[str, List[str]] = {}
    for category, phrases in TEXT_SIGNALS.items():
        hits = [phrase for phrase in phrases if phrase in lowered]
        if hits:
            category_hits[category] = hits
            detected_keywords.extend(hits)
            suspicious_phrases.extend(hits)

    weighted_score = sum(KEYWORD_WEIGHTS.get(keyword, 8) for keyword in set(detected_keywords))
    entities = extract_entities(text)
    keyword_density = round((len(detected_keywords) / total_words) * 100, 2)
    entity_bonus = min(25, (len(entities["urls"]) * 8) + (len(entities["emails"]) * 4) + (len(entities["phones"]) * 4))
    phrase_bonus = min(25, len(suspicious_phrases) * 6)
    text_score = max(0, min(100, int(round(weighted_score + entity_bonus + phrase_bonus))))

    return {
        "text_score": text_score,
        "detected_keywords": list(dict.fromkeys(detected_keywords)),
        "url_count": len(entities["urls"]),
        "suspicious_phrases": list(dict.fromkeys(suspicious_phrases)),
        "entities": entities,
        "keyword_density": keyword_density,
        "category_hits": category_hits,
    }


def _is_randomish_string(value: str) -> bool:
    """Detect labels that look machine-generated or intentionally obfuscated."""
    cleaned = re.sub(r"[^a-z0-9]", "", value.lower())
    if len(cleaned) < 8:
        return False
    digit_count = sum(ch.isdigit() for ch in cleaned)
    vowel_count = sum(ch in "aeiou" for ch in cleaned)
    return digit_count >= 2 or vowel_count <= max(1, len(cleaned) // 5)


def analyze_url_risk(urls: List[str]) -> Dict[str, Any]:
    """Score URLs for suspicious TLDs, typosquatting, long hosts, and random strings."""
    suspicious_urls: List[str] = []
    reasons: List[str] = []
    url_risk_score = 0

    for url in urls:
        try:
            parsed = urlparse(url)
            host = (parsed.netloc or parsed.path).lower()
            if not host:
                continue

            host_reasons: List[str] = []
            if len(host) > 30:
                url_risk_score += 18
                host_reasons.append("Long domain length")

            tld = f".{host.split('.')[-1]}" if "." in host else ""
            if tld in SUSPICIOUS_TLDS:
                url_risk_score += 28
                host_reasons.append(f"Suspicious TLD {tld}")

            label = host.split(".")[0]
            if _is_randomish_string(label):
                url_risk_score += 24
                host_reasons.append("Domain contains random-looking string")

            normalized_label = label.replace("1", "l").replace("0", "o").replace("5", "s")
            for brand in TRUSTED_BRANDS:
                similarity = difflib.SequenceMatcher(None, normalized_label, brand).ratio()
                if similarity >= 0.74 and label != brand and brand not in host:
                    url_risk_score += 30
                    host_reasons.append(f"Possible typosquatting of {brand}")
                    break

            if "-" in label and len(label) > 12:
                url_risk_score += 10
                host_reasons.append("Hyphenated domain pattern")

            if host_reasons:
                suspicious_urls.append(url)
                reasons.extend(f"{host}: {reason}" for reason in host_reasons)
        except Exception:
            suspicious_urls.append(url)
            reasons.append(f"{url}: Failed to parse URL safely")
            url_risk_score += 15

    return {
        "url_risk_score": max(0, min(100, int(round(url_risk_score)))),
        "suspicious_urls": list(dict.fromkeys(suspicious_urls)),
        "reasons": list(dict.fromkeys(reasons)),
    }


def analyze_brand_impersonation(sender: str, urls: List[str], text: str) -> Dict[str, Any]:
    """Flag cases where a famous brand is mentioned but the sender/domain does not match."""
    lowered_text = f"{sender} {text}".lower()
    brand_mentions = [brand for brand in BRAND_DOMAINS if brand in lowered_text]
    sender_match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender or "")
    sender_domain = sender_match.group(1).lower() if sender_match else ""

    mismatches: List[str] = []
    brand_name = ""
    expected_domain = ""
    for brand in brand_mentions:
        expected_domains = BRAND_DOMAINS[brand]
        sender_matches = any(domain in sender_domain for domain in expected_domains)
        url_matches = any(any(domain in url.lower() for domain in expected_domains) for url in urls)
        if not sender_matches and brand_mentions and urls and not url_matches:
            mismatches.append(brand)
            brand_name = brand.title()
            expected_domain = expected_domains[0]
        elif not sender_matches and not urls:
            mismatches.append(brand)
            brand_name = brand.title()
            expected_domain = expected_domains[0]

    return {
        "detected": bool(mismatches),
        "type": "brand" if mismatches else "none",
        "details": ", ".join(sorted(set(mismatches))) if mismatches else "",
        "score": min(100, len(set(mismatches)) * 35),
        "mentions": list(dict.fromkeys(brand_mentions)),
        "brand": brand_name,
        "actual_domain": sender_domain,
        "expected_domain": expected_domain,
    }


def analyze_role_impersonation(text: str) -> Dict[str, Any]:
    """Detect fake role claims like bank manager, police, or support team."""
    lowered = (text or "").lower()
    found_roles: List[str] = []
    for role_group, role_names in ROLE_PATTERNS.items():
        for role_name in role_names:
            if role_name in lowered:
                found_roles.append(role_name)

    intro_used = any(phrase in lowered for phrase in ROLE_INTRO_PHRASES)
    asks_sensitive_action = any(signal in lowered for signal in TEXT_SIGNALS["sensitive_action"])
    uses_urgency = any(signal in lowered for signal in TEXT_SIGNALS["urgency"])
    impersonation_detected = bool(found_roles and intro_used and (asks_sensitive_action or uses_urgency))
    return {
        "detected": impersonation_detected,
        "type": "role" if impersonation_detected else "none",
        "details": ", ".join(sorted(set(found_roles))) if found_roles else "",
        "score": 75 if impersonation_detected else (20 if found_roles else 0),
        "roles": list(dict.fromkeys(found_roles)),
    }


def analyze_targeting_reason(text: str, brand_mentions: List[str]) -> List[str]:
    """Explain why the message may have been tailored for this user."""
    lowered = (text or "").lower()
    reasons: List[str] = []
    if any(keyword in lowered for keyword in TARGETING_KEYWORDS["financial"]):
        reasons.append("User likely targeted due to financial context")
    if any(keyword in lowered for keyword in TARGETING_KEYWORDS["job"]):
        reasons.append("Message appears tailored to job or career-related interest")
    if any(keyword in lowered for keyword in TARGETING_KEYWORDS["shopping"]):
        reasons.append("User likely targeted with shopping or offer-based bait")
    if brand_mentions:
        reasons.append("Message tries to exploit trust in a familiar brand")
    if any(signal in lowered for signal in TEXT_SIGNALS["urgency"]):
        reasons.append("Message designed to exploit urgency and trust")
    return list(dict.fromkeys(reasons))


def _extract_claimed_location(text: str) -> str:
    lowered = (text or "").lower()
    for alias, canonical in LOCATION_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", lowered):
            return canonical
    return ""


def _infer_domain_location(urls: List[str], sender: str) -> str:
    sources: List[str] = []
    if sender:
        sender_match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender)
        if sender_match:
            sources.append(sender_match.group(1).lower())
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.netloc or parsed.path).lower()
        if host:
            sources.append(host)

    for source in sources:
        for suffix, location in sorted(TLD_LOCATION_MAP.items(), key=lambda item: len(item[0]), reverse=True):
            if source.endswith(suffix):
                return location
    return "Unknown"


def analyze_geo_context(text: str, urls: List[str], sender: str) -> Dict[str, Any]:
    """Compare claimed location in the message against a rough domain/TLD location hint."""
    claimed_location = _extract_claimed_location(text)
    actual_server_location = _infer_domain_location(urls, sender)
    mismatch = bool(claimed_location and actual_server_location != "Unknown" and claimed_location != actual_server_location)
    risk = "HIGH" if mismatch else ("MEDIUM" if claimed_location or actual_server_location != "Unknown" else "LOW")
    return {
        "claimed_location": claimed_location or "Unknown",
        "actual_server_location": actual_server_location,
        "mismatch": mismatch,
        "risk": risk,
    }


def simulate_website_preview(urls: List[str]) -> Dict[str, Any]:
    """Fetch a small HTML preview without executing JavaScript or opening the site in a browser."""
    if not urls:
        return {
            "title": "",
            "has_login_form": False,
            "suspicious": False,
            "reason": "No URL detected",
        }

    target_url = urls[0]
    try:
        response = requests.get(
            target_url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 SafePreview/1.0"},
            stream=True,
        )
        content = response.raw.read(100000, decode_content=True).decode("utf-8", errors="ignore")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
        has_password = bool(re.search(r'type=["\']password["\']', content, re.IGNORECASE))
        has_form = "<form" in content.lower()
        suspicious = has_password or ("login" in content.lower() and has_form)
        reason = "Fake login page detected" if suspicious else "No obvious fake-login indicators in HTML preview"
        return {
            "title": title,
            "has_login_form": bool(has_form and has_password),
            "suspicious": suspicious,
            "reason": reason,
        }
    except Exception as exc:
        return {
            "title": "",
            "has_login_form": False,
            "suspicious": False,
            "reason": f"Safe preview unavailable: {exc}",
        }


def classify_phishing_type(*texts: str) -> str:
    """Choose the phishing category that best matches the analyzed text."""
    combined_text = " ".join(filter(None, texts)).lower()
    best_type = "unknown"
    best_hits = 0

    for phishing_type, keywords in PHISHING_TYPE_KEYWORDS.items():
        hits = sum(1 for keyword in keywords if keyword in combined_text)
        if hits > best_hits:
            best_hits = hits
            best_type = phishing_type

    return best_type


def combine_risk_scores(text_score: int, url_score: int, steg_score: int, impersonation_score: int) -> int:
    """Blend all major channels into one final phishing score."""
    final_risk = (
        (0.35 * text_score)
        + (0.25 * url_score)
        + (0.20 * steg_score)
        + (0.20 * impersonation_score)
    )
    return max(0, min(100, int(round(final_risk))))


def detect_high_risk_text_pattern(text_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Catch obvious scam combinations that should be phishing even without a strong ML score."""
    category_hits = text_analysis.get("category_hits", {})
    has_authority = bool(category_hits.get("authority"))
    has_sensitive_action = bool(category_hits.get("sensitive_action"))
    has_fear = bool(category_hits.get("fear"))
    has_urgency = bool(category_hits.get("urgency"))

    if has_authority and has_sensitive_action and (has_fear or has_urgency):
        return {
            "detected": True,
            "risk_floor": 92,
            "reason": "Combines authority claims with OTP/password request and fear or urgency tactics",
        }

    if has_sensitive_action and has_fear:
        return {
            "detected": True,
            "risk_floor": 82,
            "reason": "Requests sensitive action while threatening account impact",
        }

    return {"detected": False, "risk_floor": 0, "reason": ""}


def determine_verdict(text_score: int, url_score: int, steg_score: int, impersonation_score: int,
                      risk_score: int) -> Tuple[str, str]:
    """Convert numeric values into the final phishing verdict."""
    if url_score > 70 or text_score > 75 or steg_score > 60 or impersonation_score > 65 or risk_score >= 75:
        return "PHISHING", "HIGH"
    if risk_score >= 45 or text_score >= 45 or url_score >= 40 or steg_score >= 35 or impersonation_score >= 35:
        return "SUSPICIOUS", "MEDIUM"
    return "SAFE", "LOW"


def verdict_from_risk(risk_score: int) -> str:
    """Map the internal verdict to the older labels already used by the UI."""
    verdict, _ = determine_verdict(risk_score, 0, 0, 0, risk_score)
    if verdict == "PHISHING":
        return "Malicious"
    if verdict == "SUSPICIOUS":
        return "Suspicious"
    return "Safe"


def build_reasoning(text_analysis: Dict[str, Any], url_analysis: Dict[str, Any], impersonation: Dict[str, Any],
                    steg_reasons: List[str]) -> List[str]:
    """Create the human-readable reasoning list shown in the UI."""
    why_flagged: List[str] = []
    if impersonation["type"] == "brand" and impersonation["details"]:
        why_flagged.append(f"Mentions brand but domain/sender does not match: {impersonation['details']}")
    if impersonation["type"] == "role" and impersonation["details"]:
        why_flagged.append(f"Claims to be a sensitive role: {impersonation['details']}")
    if url_analysis["suspicious_urls"]:
        why_flagged.append("Suspicious URL detected")
    if text_analysis["category_hits"].get("urgency"):
        why_flagged.append("Uses urgency language")
    if text_analysis["category_hits"].get("fear"):
        why_flagged.append("Uses fear tactics")
    if text_analysis["category_hits"].get("authority"):
        why_flagged.append("Mimics authority or trusted organization language")
    if text_analysis["category_hits"].get("sensitive_action"):
        why_flagged.append("Requests sensitive action such as password, OTP, or account verification")
    if steg_reasons:
        why_flagged.append("Possible hidden data in image")
    return list(dict.fromkeys(why_flagged))


def build_summary(verdict: str, impersonation: Dict[str, Any], url_analysis: Dict[str, Any],
                  text_analysis: Dict[str, Any]) -> str:
    """Create a short 2-line plain-English explanation for the user."""
    first_line = "This message looks safe based on the signals we checked."
    second_line = "No strong phishing tricks were detected."

    if verdict == "PHISHING":
        if impersonation.get("detected"):
            first_line = "This message appears to impersonate a trusted brand or authority."
        elif url_analysis.get("suspicious_urls"):
            first_line = "This message contains a suspicious link that could lead to a fake website."
        else:
            first_line = "This message shows strong signs of phishing."

        if text_analysis["category_hits"].get("urgency") or text_analysis["category_hits"].get("sensitive_action"):
            second_line = "It uses urgency or sensitive-action requests to pressure the user into acting quickly."
        else:
            second_line = "The content tries to build trust and push the user toward a risky action."
    elif verdict == "SUSPICIOUS":
        first_line = "This message shows some warning signs and should be treated carefully."
        second_line = "It may be trying to build urgency, trust, or curiosity before asking for action."

    return f"{first_line}\n{second_line}"


def build_analysis_result(*, text: str, sender: str, steg_score: int = 0,
                          steg_reasons: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run one complete multilingual phishing analysis over a text block."""
    language = detect_and_translate_text(text)
    translated_text = language["translated_text"]
    original_text = language.get("original_text", text or "")
    # Analyze both the English version and the original text so phishing can
    # still be caught when translation is unavailable or imperfect.
    analysis_text = translated_text
    if original_text.strip() and original_text.strip() not in analysis_text:
        analysis_text = f"{translated_text}\n{original_text}".strip()

    nlp_result = analyze_with_nlp(translated_text or original_text)
    text_analysis = analyze_text_features(analysis_text)
    text_score = max(int(nlp_result["score"]), int(text_analysis["text_score"]))
    high_risk_pattern = detect_high_risk_text_pattern(text_analysis)
    if high_risk_pattern["detected"]:
        text_score = max(text_score, high_risk_pattern["risk_floor"])
    url_analysis = analyze_url_risk(text_analysis["entities"]["urls"])
    brand_impersonation = analyze_brand_impersonation(sender, text_analysis["entities"]["urls"], analysis_text)
    role_impersonation = analyze_role_impersonation(analysis_text)

    if brand_impersonation["score"] >= role_impersonation["score"]:
        impersonation = {
            "detected": brand_impersonation["detected"] or role_impersonation["detected"],
            "type": brand_impersonation["type"] if brand_impersonation["detected"] else role_impersonation["type"],
            "details": brand_impersonation["details"] if brand_impersonation["detected"] else role_impersonation["details"],
        }
    else:
        impersonation = {
            "detected": brand_impersonation["detected"] or role_impersonation["detected"],
            "type": role_impersonation["type"],
            "details": role_impersonation["details"],
        }

    impersonation_score = max(brand_impersonation["score"], role_impersonation["score"])
    risk_score = combine_risk_scores(text_score, int(url_analysis["url_risk_score"]), steg_score, impersonation_score)
    if high_risk_pattern["detected"]:
        risk_score = max(risk_score, high_risk_pattern["risk_floor"])
    verdict, suspicion_level = determine_verdict(text_score, int(url_analysis["url_risk_score"]), steg_score, impersonation_score, risk_score)
    phishing_type = "impersonation" if impersonation["detected"] else classify_phishing_type(analysis_text)
    targeting_reason = analyze_targeting_reason(analysis_text, brand_impersonation.get("mentions", []))
    geo_analysis = analyze_geo_context(analysis_text, text_analysis["entities"]["urls"], sender)
    website_preview = simulate_website_preview(text_analysis["entities"]["urls"])
    confidence = max(
        risk_score,
        min(100, int(round((text_score * 0.4) + (int(url_analysis["url_risk_score"]) * 0.25) + (steg_score * 0.15) + (impersonation_score * 0.2)))),
    )

    reasoning = build_reasoning(text_analysis, url_analysis, impersonation, steg_reasons or [])
    if high_risk_pattern["detected"]:
        reasoning.append(high_risk_pattern["reason"])
    if nlp_result["label"] == "PHISHING":
        reasoning.append(nlp_result["reason"])
    if geo_analysis["mismatch"]:
        reasoning.append("Claimed location does not match domain location context")
    if website_preview["suspicious"]:
        reasoning.append(website_preview["reason"])

    return {
        "verdict": verdict,
        "confidence": confidence,
        "confidence_score": confidence,
        "risk_score": risk_score,
        "phishing_type": phishing_type,
        "summary": build_summary(verdict, impersonation, url_analysis, text_analysis),
        "language": language,
        "impersonation": impersonation,
        "geo_analysis": geo_analysis,
        "targeting_reason": targeting_reason,
        "website_preview": website_preview,
        "scores": {
            "text": text_score,
            "url": int(url_analysis["url_risk_score"]),
            "steg": steg_score,
            "impersonation": impersonation_score,
        },
        "reasoning": list(dict.fromkeys(reasoning)),
        "text_score": text_score,
        "url_score": int(url_analysis["url_risk_score"]),
        "steg_score": steg_score,
        "impersonation_score": impersonation_score,
        "keyword_density": text_analysis["keyword_density"],
        "suspicion_level": suspicion_level,
        "detected_keywords": text_analysis["detected_keywords"],
        "suspicious_phrases": text_analysis["suspicious_phrases"],
        "entities": text_analysis["entities"],
        "stats": {
            "url_count": text_analysis["url_count"],
            "keyword_matches": len(text_analysis["detected_keywords"]),
            "suspicious_phrases": len(text_analysis["suspicious_phrases"]),
        },
        "url_risk_analysis": url_analysis,
    }


def history_item(
    *,
    unique_key: str,
    source_type: str,
    sender: str,
    message_text: str,
    verdict: str,
    phish_score: int,
    nlp_label: str,
    detected_url: Optional[str] = None,
    domain_name: Optional[str] = None,
    has_ssl: Optional[bool] = None,
    attachment_type: Optional[str] = None,
    reasons: Optional[List[str]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "id": len(ANALYSIS_HISTORY) + 1,
        "unique_key": unique_key,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "sender": sender or "Unknown",
        "message_text": message_text,
        "source_type": source_type,
        "detected_url": detected_url,
        "domain_name": domain_name,
        "domain_age_days": None,
        "has_ssl": has_ssl,
        "nlp_label": nlp_label,
        "phish_score": phish_score,
        "verdict": verdict,
        "attachment_type": attachment_type,
        "reasons": reasons or [],
        "details": details or {},
    }


def get_archive_connection() -> Optional[Any]:
    """Open a MySQL connection for the existing threat_history table."""
    if pymysql is None:
        return None
    try:
        return pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )
    except Exception:
        return None


def init_archive_db() -> None:
    """Verify that MySQL storage is reachable without creating a new table."""
    connection = get_archive_connection()
    if connection is None:
        return
    connection.close()


def load_history_from_db() -> None:
    """Load archive rows from the existing MySQL threat_history table."""
    ANALYSIS_HISTORY.clear()
    connection = get_archive_connection()
    if connection is None:
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT id, timestamp, source_type, sender, message_text, detected_url,
                       domain_name, domain_age_days, has_ssl, nlp_label, phish_score, verdict
                FROM {MYSQL_TABLE}
                ORDER BY timestamp DESC, id DESC
                """
            )
            rows = cursor.fetchall()
    finally:
        connection.close()

    for row in rows:
        cache_key = (
            f"{row.get('source_type', 'gmail')}|"
            f"{row.get('timestamp', '')}|"
            f"{row.get('sender', '')}|"
            f"{row.get('message_text', '')}"
        )
        ANALYSIS_HISTORY.append(
            {
                "id": row["id"],
                "unique_key": cache_key,
                "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(row["timestamp"], "strftime") else str(row["timestamp"]),
                "sender": row["sender"],
                "message_text": row["message_text"],
                "source_type": row["source_type"],
                "detected_url": row["detected_url"],
                "domain_name": row["domain_name"],
                "domain_age_days": row["domain_age_days"],
                "has_ssl": bool(row["has_ssl"]) if row["has_ssl"] is not None else None,
                "nlp_label": row["nlp_label"],
                "phish_score": row["phish_score"],
                "verdict": row["verdict"],
                "attachment_type": None,
                "reasons": DETAIL_CACHE.get(cache_key, {}).get("reasoning", []),
                "details": DETAIL_CACHE.get(cache_key, {}),
            }
        )


def add_history(entry: Dict[str, Any]) -> None:
    """Insert one row into the existing MySQL table and keep rich UI details in memory."""
    cache_key = entry.get("unique_key") or (
        f"{entry.get('source_type', 'gmail')}|"
        f"{entry.get('timestamp', '')}|"
        f"{entry.get('sender', '')}|"
        f"{entry.get('message_text', '')}"
    )
    DETAIL_CACHE[cache_key] = entry.get("details", {})

    connection = get_archive_connection()
    if connection is None:
        load_history_from_db()
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO {MYSQL_TABLE} (
                    timestamp, source_type, sender, message_text, detected_url,
                    domain_name, domain_age_days, has_ssl, nlp_label, phish_score, verdict
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    entry.get("timestamp"),
                    entry.get("source_type"),
                    entry.get("sender"),
                    entry.get("message_text"),
                    entry.get("detected_url"),
                    entry.get("domain_name"),
                    entry.get("domain_age_days"),
                    int(entry["has_ssl"]) if entry.get("has_ssl") is not None else None,
                    entry.get("nlp_label"),
                    entry.get("phish_score"),
                    entry.get("verdict"),
                ),
            )
        connection.commit()
    except Exception:
        connection.rollback()
    finally:
        connection.close()

    load_history_from_db()


def decode_base64_data(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def parse_internal_date(message: Dict[str, Any]) -> Optional[str]:
    internal_date = message.get("internalDate")
    if internal_date:
        dt = datetime.fromtimestamp(int(internal_date) / 1000.0, tz=timezone.utc)
        return dt.isoformat()

    headers = message.get("payload", {}).get("headers", [])
    date_header = next((h.get("value") for h in headers if h.get("name", "").lower() == "date"), None)
    if not date_header:
        return None

    try:
        return parsedate_to_datetime(date_header).isoformat()
    except Exception:
        return None


def get_header(headers: List[Dict[str, str]], name: str, default: str = "") -> str:
    target = name.lower()
    for header in headers:
        if header.get("name", "").lower() == target:
            return header.get("value", default)
    return default


def extract_email_body(payload: Dict[str, Any]) -> str:
    collected_parts: List[str] = []

    def walk(part: Dict[str, Any]) -> None:
        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")

        if mime_type == "text/plain" and data:
            try:
                collected_parts.append(decode_base64_data(data).decode("utf-8", errors="ignore"))
            except Exception:
                pass

        for child in part.get("parts", []) or []:
            walk(child)

    walk(payload)
    if collected_parts:
        return "\n".join(collected_parts).strip()

    fallback_data = payload.get("body", {}).get("data")
    if fallback_data:
        try:
            return decode_base64_data(fallback_data).decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    return ""


def collect_attachments(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    attachments: List[Dict[str, Any]] = []

    def walk(part: Dict[str, Any]) -> None:
        filename = part.get("filename")
        body = part.get("body", {})
        attachment_id = body.get("attachmentId")
        size = int(body.get("size", 0) or 0)
        inline_data = body.get("data")

        if filename and (attachment_id or inline_data):
            attachments.append(
                {
                    "filename": filename,
                    "mime_type": part.get("mimeType", "application/octet-stream"),
                    "attachment_id": attachment_id,
                    "size": size,
                    "inline_data": inline_data,
                }
            )

        for child in part.get("parts", []) or []:
            walk(child)

    walk(payload)
    return attachments


def summarize_payload_parts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []

    def walk(part: Dict[str, Any], depth: int = 0) -> None:
        body = part.get("body", {})
        summaries.append(
            {
                "depth": depth,
                "mime_type": part.get("mimeType"),
                "filename": part.get("filename"),
                "has_attachment_id": bool(body.get("attachmentId")),
                "has_inline_data": bool(body.get("data")),
                "size": int(body.get("size", 0) or 0),
            }
        )
        for child in part.get("parts", []) or []:
            walk(child, depth + 1)

    walk(payload)
    return summaries


def infer_attachment_type(filename: str, mime_type: str) -> Optional[str]:
    lowered = (mime_type or "").lower()
    guessed_mime, _ = mimetypes.guess_type(filename)
    lowered_guess = (guessed_mime or "").lower()

    if lowered in SUPPORTED_IMAGE_MIME_TYPES or lowered_guess in SUPPORTED_IMAGE_MIME_TYPES:
        return "image"
    if lowered == "application/pdf" or lowered_guess == "application/pdf":
        return "pdf"
    if lowered in SUPPORTED_TEXT_MIME_TYPES or lowered_guess in SUPPORTED_TEXT_MIME_TYPES:
        return "text"
    return None


def download_attachment(service: Any, message_id: str, attachment_meta: Dict[str, Any], temp_dir: str) -> str:
    if attachment_meta["size"] > TOKEN_SIZE_LIMIT:
        raise ValueError("Attachment exceeds 10MB size limit")

    raw_data: bytes
    if attachment_meta.get("inline_data"):
        raw_data = decode_base64_data(attachment_meta["inline_data"])
    elif attachment_meta.get("attachment_id"):
        attachment = (
            service.users()
            .messages()
            .attachments()
            .get(userId="me", messageId=message_id, id=attachment_meta["attachment_id"])
            .execute()
        )
        raw_data = decode_base64_data(attachment["data"])
    else:
        raise ValueError("Attachment payload missing downloadable data")

    if len(raw_data) > TOKEN_SIZE_LIMIT:
        raise ValueError("Downloaded attachment exceeds 10MB size limit")

    file_path = os.path.join(temp_dir, os.path.basename(attachment_meta["filename"]))
    with open(file_path, "wb") as handle:
        handle.write(raw_data)
    return file_path


def extract_pdf_text(file_path: str) -> str:
    try:
        reader = PdfReader(file_path)
        text_fragments = [page.extract_text() or "" for page in reader.pages]
        return " ".join(fragment.strip() for fragment in text_fragments if fragment).strip()
    except Exception:
        try:
            from pdfminer.high_level import extract_text

            return " ".join(extract_text(file_path).split())
        except Exception:
            return ""


def extract_text_file(file_path: str) -> str:
    with open(file_path, "rb") as handle:
        content = handle.read(TOKEN_SIZE_LIMIT + 1)
    if len(content) > TOKEN_SIZE_LIMIT:
        raise ValueError("Text file exceeds 10MB size limit")
    return content.decode("utf-8", errors="ignore")


def attachment_result(file_name: str, attachment_type: str, extracted_text: str, sender: str,
                      steg_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build the final JSON for one attachment after text extraction is done."""
    steg_result = steg_result or {"steg_score": 0, "reasons": []}
    analysis = build_analysis_result(
        text=extracted_text,
        sender=sender,
        steg_score=int(steg_result.get("steg_score", steg_result.get("steg_risk_score", 0))),
        steg_reasons=steg_result.get("reasons", []),
    )
    return {
        "file_name": file_name,
        "type": attachment_type,
        "extracted_text": extracted_text[:1200],
        "phishing_detected": analysis["verdict"] == "PHISHING",
        **analysis,
    }


def analyze_attachment(service: Any, message_id: str, attachment_meta: Dict[str, Any], sender: str,
                       temp_dir: str) -> Dict[str, Any]:
    attachment_type = infer_attachment_type(attachment_meta["filename"], attachment_meta["mime_type"])
    if not attachment_type:
        return {
            "file_name": attachment_meta["filename"],
            "type": "unsupported",
            "extracted_text": "",
            "verdict": "SAFE",
            "confidence": 25,
            "confidence_score": 25,
            "risk_score": 0,
            "phishing_type": "unknown",
            "language": {"detected": "en", "translated_text": ""},
            "impersonation": {"detected": False, "type": "none", "details": ""},
            "scores": {"text": 0, "url": 0, "steg": 0, "impersonation": 0},
            "reasoning": ["Unsupported attachment type"],
            "text_score": 0,
            "url_score": 0,
            "steg_score": 0,
            "impersonation_score": 0,
            "keyword_density": 0,
            "suspicion_level": "LOW",
            "detected_keywords": [],
            "suspicious_phrases": [],
            "entities": {"urls": [], "emails": [], "phones": []},
            "stats": {"url_count": 0, "keyword_matches": 0, "suspicious_phrases": 0},
            "url_risk_analysis": {"url_risk_score": 0, "suspicious_urls": [], "reasons": []},
        }

    file_path = download_attachment(service, message_id, attachment_meta, temp_dir)
    extracted_text = ""

    if attachment_type == "image":
        image_result = analyze_image_for_steg(file_path)
        extracted_text = image_result["extracted_text"]
        return attachment_result(attachment_meta["filename"], attachment_type, extracted_text, sender, image_result)

    if attachment_type == "pdf":
        extracted_text = extract_pdf_text(file_path)
        result = attachment_result(attachment_meta["filename"], attachment_type, extracted_text, sender)
        if extracted_text:
            result["reasoning"] = list(dict.fromkeys(["PDF text extracted"] + result["reasoning"]))
        return result

    extracted_text = extract_text_file(file_path)
    result = attachment_result(attachment_meta["filename"], attachment_type, extracted_text, sender)
    if extracted_text:
        result["reasoning"] = list(dict.fromkeys(["Text file content extracted"] + result["reasoning"]))
    return result


def analyze_email_message(service: Any, message: Dict[str, Any]) -> Dict[str, Any]:
    payload = message.get("payload", {})
    headers = payload.get("headers", [])
    sender = get_header(headers, "From", "Unknown")
    body_text = extract_email_body(payload)
    attachments_meta = collect_attachments(payload)
    body_analysis = build_analysis_result(text=body_text, sender=sender)

    attachment_results: List[Dict[str, Any]] = []
    temp_dir_obj = tempfile.TemporaryDirectory(prefix="gmail_scan_")

    try:
        for attachment_meta in attachments_meta:
            try:
                attachment_results.append(
                    analyze_attachment(
                        service=service,
                        message_id=message["id"],
                        attachment_meta=attachment_meta,
                        sender=sender,
                        temp_dir=temp_dir_obj.name,
                    )
                )
            except ValueError as exc:
                attachment_results.append(
                    {
                        "file_name": attachment_meta["filename"],
                        "type": infer_attachment_type(attachment_meta["filename"], attachment_meta["mime_type"]) or "unsupported",
                        "phishing_detected": False,
                        "phishing_type": "unknown",
                        "risk_score": 0,
                        "confidence_score": 35,
                        "suspicion_level": "LOW",
                        "verdict": "SAFE",
                        "reasoning": [str(exc)],
                        "extracted_text": "",
                        "language": {"detected": "en", "translated_text": ""},
                        "impersonation": {"detected": False, "type": "none", "details": ""},
                        "text_score": 0,
                        "url_score": 0,
                        "steg_score": 0,
                        "impersonation_score": 0,
                        "scores": {"text": 0, "url": 0, "steg": 0, "impersonation": 0},
                        "stats": {"url_count": 0, "keyword_matches": 0, "suspicious_phrases": 0},
                        "entities": {"urls": [], "emails": [], "phones": []},
                        "detected_keywords": [],
                        "suspicious_phrases": [],
                        "keyword_density": 0,
                        "url_risk_analysis": {"url_risk_score": 0, "suspicious_urls": [], "reasons": []},
                    }
                )
            except Exception as exc:
                attachment_type = infer_attachment_type(attachment_meta["filename"], attachment_meta["mime_type"]) or "unknown"
                attachment_results.append(
                    {
                        "file_name": attachment_meta["filename"],
                        "type": attachment_type,
                        "phishing_detected": False,
                        "phishing_type": "unknown",
                        "risk_score": 0,
                        "confidence_score": 40,
                        "suspicion_level": "LOW",
                        "verdict": "SAFE",
                        "reasoning": [f"Attachment analysis failed safely: {exc}"],
                        "extracted_text": "",
                        "language": {"detected": "en", "translated_text": ""},
                        "impersonation": {"detected": False, "type": "none", "details": ""},
                        "text_score": 0,
                        "url_score": 0,
                        "steg_score": 0,
                        "impersonation_score": 0,
                        "scores": {"text": 0, "url": 0, "steg": 0, "impersonation": 0},
                        "stats": {"url_count": 0, "keyword_matches": 0, "suspicious_phrases": 0},
                        "entities": {"urls": [], "emails": [], "phones": []},
                        "detected_keywords": [],
                        "suspicious_phrases": [],
                        "keyword_density": 0,
                        "url_risk_analysis": {"url_risk_score": 0, "suspicious_urls": [], "reasons": []},
                    }
                )
    finally:
        temp_dir_obj.cleanup()

    highest_attachment_risk = max((item["risk_score"] for item in attachment_results), default=0)
    highest_attachment = max(attachment_results, key=lambda item: item["risk_score"], default=None)
    final_risk = max(body_analysis["risk_score"], highest_attachment_risk)
    final_verdict = body_analysis["verdict"]
    final_confidence = body_analysis["confidence"]
    final_phishing_type = body_analysis["phishing_type"]
    final_reasoning = list(body_analysis["reasoning"])
    final_scores = dict(body_analysis["scores"])
    final_impersonation = dict(body_analysis["impersonation"])
    if highest_attachment and highest_attachment["risk_score"] >= body_analysis["risk_score"]:
        final_verdict = highest_attachment["verdict"]
        final_confidence = highest_attachment["confidence"]
        final_phishing_type = highest_attachment["phishing_type"]
        final_reasoning = list(highest_attachment["reasoning"])
        final_scores = dict(highest_attachment["scores"])
        final_impersonation = dict(highest_attachment["impersonation"])

    return {
        "email_id": message["id"],
        "overall_risk_score": final_risk,
        "risk_score": final_risk,
        "phishing_detected": final_verdict == "PHISHING",
        "verdict": final_verdict,
        "confidence": final_confidence,
        "confidence_score": final_confidence,
        "phishing_type": final_phishing_type,
        "suspicion_level": body_analysis["suspicion_level"],
        "attachments": attachment_results,
        "attachment_count": len(attachments_meta),
        "sender": sender,
        "subject": get_header(headers, "Subject", ""),
        "received_at": parse_internal_date(message),
        "language": body_analysis["language"],
        "impersonation": final_impersonation,
        "scores": final_scores,
        "reasoning": final_reasoning,
        "body_analysis": body_analysis,
    }


def legacy_stream_rows(email_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    sender = email_analysis.get("sender", "Unknown")
    subject = email_analysis.get("subject", "")
    body_analysis = email_analysis.get("body_analysis", {})
    overall_risk = int(email_analysis.get("overall_risk_score", 0))

    if email_analysis.get("attachments"):
        for attachment in email_analysis["attachments"]:
            risk_score = int(attachment.get("risk_score", 0))
            verdict = "Safe" if attachment.get("verdict") == "SAFE" else "Suspicious" if attachment.get("verdict") == "SUSPICIOUS" else "Malicious"
            row = {
                "sender": sender,
                "domain_name": attachment.get("file_name", "Attachment"),
                "nlp_label": attachment.get("verdict", "SAFE"),
                "phish_score": risk_score,
                "verdict": verdict,
                "item_kind": "attachment",
                "attachment_type": attachment.get("type", "unknown"),
                "reasons": attachment.get("reasoning", []),
                "subject": subject,
                "attachment_count": int(email_analysis.get("attachment_count", 0)),
                "details": {
                    "file_name": attachment.get("file_name", "Attachment"),
                    "type": attachment.get("type", "unknown"),
                    "verdict": attachment.get("verdict", "SAFE"),
                    "malicious": bool(attachment.get("phishing_detected")),
                    "risk_score": risk_score,
                    "confidence_score": int(attachment.get("confidence_score", attachment.get("confidence", risk_score))),
                    "suspicion_level": attachment.get("suspicion_level", "LOW"),
                    "phishing_type": attachment.get("phishing_type", "unknown"),
                    "text_phishing_score": int(attachment.get("text_score", 0)),
                    "url_score": int(attachment.get("url_score", 0)),
                    "steg_risk_score": int(attachment.get("steg_score", attachment.get("steg_risk_score", 0))),
                    "keyword_score": min(100, len(attachment.get("detected_keywords", [])) * 10),
                    "reasons": attachment.get("reasoning", []),
                    "extracted_text": attachment.get("extracted_text", ""),
                    "detected_keywords": attachment.get("detected_keywords", []),
                    "suspicious_phrases": attachment.get("suspicious_phrases", []),
                    "keyword_density": attachment.get("keyword_density", 0),
                    "entities": attachment.get("entities", {}),
                    "stats": attachment.get("stats", {}),
                    "language": attachment.get("language", {}),
                    "impersonation": attachment.get("impersonation", {}),
                    "geo_analysis": attachment.get("geo_analysis", {}),
                    "targeting_reason": attachment.get("targeting_reason", []),
                    "website_preview": attachment.get("website_preview", {}),
                    "summary": attachment.get("summary", ""),
                    "scores": attachment.get("scores", {}),
                    "reasoning": attachment.get("reasoning", []),
                    "subject": subject,
                },
            }
            rows.append(row)
            add_history(
                history_item(
                    unique_key=f"{email_analysis.get('email_id', 'unknown')}:attachment:{attachment.get('file_name', 'unknown')}",
                    source_type="gmail",
                    sender=sender,
                    message_text=subject,
                    verdict=verdict,
                    phish_score=risk_score,
                    nlp_label=row["nlp_label"],
                    domain_name=attachment.get("file_name"),
                    attachment_type=attachment.get("type"),
                    reasons=attachment.get("reasoning", []),
                    details=row["details"],
                )
            )
    else:
        verdict = verdict_from_risk(overall_risk)
        row = {
            "sender": sender,
            "domain_name": email_analysis.get("subject") or "No Link",
            "nlp_label": email_analysis.get("verdict", "SAFE"),
            "phish_score": overall_risk,
            "verdict": verdict,
            "item_kind": "email",
            "attachment_type": None,
            "reasons": body_analysis.get("reasoning", []),
            "subject": subject,
            "attachment_count": int(email_analysis.get("attachment_count", 0)),
            "details": {
                "file_name": subject or "Email Body",
                "type": "email",
                "verdict": email_analysis.get("verdict", "SAFE"),
                "malicious": email_analysis.get("verdict") == "PHISHING",
                "risk_score": int(email_analysis.get("risk_score", overall_risk)),
                "confidence_score": int(email_analysis.get("confidence_score", email_analysis.get("confidence", overall_risk))),
                "suspicion_level": email_analysis.get("suspicion_level", "LOW"),
                "phishing_type": email_analysis.get("phishing_type", "unknown"),
                "text_phishing_score": int(body_analysis.get("text_score", 0)),
                "url_score": int(body_analysis.get("url_score", 0)),
                "steg_risk_score": 0,
                "keyword_score": min(100, len(body_analysis.get("detected_keywords", [])) * 10),
                "reasons": body_analysis.get("reasoning", []),
                "extracted_text": body_analysis.get("language", {}).get("translated_text", ""),
                "detected_keywords": body_analysis.get("detected_keywords", []),
                "suspicious_phrases": body_analysis.get("suspicious_phrases", []),
                "keyword_density": body_analysis.get("keyword_density", 0),
                "entities": body_analysis.get("entities", {}),
                "stats": {
                    "url_count": body_analysis.get("stats", {}).get("url_count", 0),
                    "keyword_matches": body_analysis.get("stats", {}).get("keyword_matches", 0),
                    "suspicious_phrases": body_analysis.get("stats", {}).get("suspicious_phrases", 0),
                },
                "language": body_analysis.get("language", {}),
                "impersonation": email_analysis.get("impersonation", {}),
                "geo_analysis": body_analysis.get("geo_analysis", {}),
                "targeting_reason": body_analysis.get("targeting_reason", []),
                "website_preview": body_analysis.get("website_preview", {}),
                "summary": email_analysis.get("summary", body_analysis.get("summary", "")),
                "scores": email_analysis.get("scores", {}),
                "reasoning": email_analysis.get("reasoning", []),
                "subject": subject,
            },
        }
        rows.append(row)
        add_history(
            history_item(
                unique_key=f"{email_analysis.get('email_id', 'unknown')}:email",
                source_type="gmail",
                sender=sender,
                message_text=subject,
                verdict=verdict,
                phish_score=overall_risk,
                nlp_label=row["nlp_label"],
                domain_name=email_analysis.get("subject"),
                reasons=body_analysis.get("reasoning", []),
                details=row["details"],
            )
        )

    if body_analysis.get("text_score", 0):
        add_history(
            history_item(
                unique_key=f"{email_analysis.get('email_id', 'unknown')}:body",
                source_type="gmail",
                sender=sender,
                message_text=subject,
                verdict=verdict_from_risk(int(body_analysis["text_score"])),
                phish_score=int(body_analysis["text_score"]),
                nlp_label="PHISHING" if int(body_analysis["text_score"]) >= PHISHING_THRESHOLD else "SAFE",
                domain_name="Email Body",
                reasons=body_analysis.get("reasoning", []),
                details={
                    "file_name": "Email Body",
                    "type": "email_body",
                    "verdict": email_analysis.get("verdict", "SAFE"),
                    "risk_score": int(body_analysis["text_score"]),
                    "confidence_score": int(email_analysis.get("confidence_score", email_analysis.get("confidence", body_analysis["text_score"]))),
                    "phishing_type": email_analysis.get("phishing_type", "unknown"),
                    "language": body_analysis.get("language", {}),
                    "impersonation": email_analysis.get("impersonation", {}),
                    "geo_analysis": body_analysis.get("geo_analysis", {}),
                    "targeting_reason": body_analysis.get("targeting_reason", []),
                    "website_preview": body_analysis.get("website_preview", {}),
                    "scores": email_analysis.get("scores", {}),
                    "reasoning": body_analysis.get("reasoning", []),
                    "entities": body_analysis.get("entities", {}),
                    "stats": body_analysis.get("stats", {}),
                    "summary": email_analysis.get("summary", body_analysis.get("summary", "")),
                    "extracted_text": body_analysis.get("language", {}).get("translated_text", ""),
                },
            )
        )

    return rows


def fetch_recent_messages(service: Any, days: int, limit: int) -> List[Dict[str, Any]]:
    """Fetch all Gmail messages from the last N days, with pagination instead of a tiny single page."""
    query = f"newer_than:{max(1, days)}d"
    max_to_fetch = limit if limit and limit > 0 else None
    message_refs: List[Dict[str, Any]] = []
    page_token: Optional[str] = None

    while True:
        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                q=query,
                maxResults=100,
                pageToken=page_token,
            )
            .execute()
        )
        message_refs.extend(response.get("messages", []))
        if max_to_fetch is not None and len(message_refs) >= max_to_fetch:
            message_refs = message_refs[:max_to_fetch]
            break
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    full_messages: List[Dict[str, Any]] = []
    for item in message_refs:
        full_messages.append(service.users().messages().get(userId="me", id=item["id"], format="full").execute())
    return full_messages


@app.route("/")
def index() -> Any:
    if os.path.exists(LEGACY_FRONTEND_FILE):
        return send_file(LEGACY_FRONTEND_FILE)
    return jsonify({"message": "Frontend not found", "expected": LEGACY_FRONTEND_FILE}), 404


@app.route("/login")
def login() -> Any:
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for("callback", _external=True)
    authorization_url, state = flow.authorization_url(access_type="offline", prompt="consent")
    session["state"] = state
    session["code_verifier"] = flow.code_verifier
    return redirect(authorization_url)


@app.route("/callback")
def callback() -> Any:
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES, state=session["state"])
    flow.redirect_uri = url_for("callback", _external=True)
    flow.code_verifier = session["code_verifier"]
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    return redirect(url_for("index"))


@app.route("/scan-gmail", methods=["GET"])
def scan_gmail() -> Any:
    try:
        days = int(request.args.get("days", 3))
        limit = int(request.args.get("limit", 10))

        creds = get_gmail_credentials()
        service = build("gmail", "v1", credentials=creds)
        messages = fetch_recent_messages(service, days=days, limit=limit)
        analyzed = [analyze_email_message(service, message) for message in messages]

        return jsonify({"emails": analyzed, "count": len(analyzed)})
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except Exception as exc:
        return jsonify({"error": f"Gmail scan failed safely: {exc}"}), 500


@app.route("/debug-gmail-attachments", methods=["GET"])
def debug_gmail_attachments() -> Any:
    try:
        days = int(request.args.get("days", 3))
        limit = int(request.args.get("limit", 10))

        creds = get_gmail_credentials()
        service = build("gmail", "v1", credentials=creds)
        messages = fetch_recent_messages(service, days=days, limit=limit)

        debug_rows: List[Dict[str, Any]] = []
        for message in messages:
            payload = message.get("payload", {})
            headers = payload.get("headers", [])
            attachments = collect_attachments(payload)
            debug_rows.append(
                {
                    "email_id": message.get("id"),
                    "sender": get_header(headers, "From", "Unknown"),
                    "subject": get_header(headers, "Subject", ""),
                    "attachment_count": len(attachments),
                    "attachments": attachments,
                    "payload_parts": summarize_payload_parts(payload),
                }
            )

        return jsonify({"emails": debug_rows, "count": len(debug_rows)})
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except Exception as exc:
        return jsonify({"error": f"Debug Gmail attachment inspection failed: {exc}"}), 500


@app.route("/scan-gmail-stream")
def scan_gmail_stream() -> Any:
    try:
        creds = get_gmail_credentials()
        service = build("gmail", "v1", credentials=creds)
        messages = fetch_recent_messages(service, days=3, limit=0)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except Exception as exc:
        return jsonify({"error": f"Gmail scan failed safely: {exc}"}), 500

    def generate() -> Any:
        for message in messages:
            try:
                analyzed = analyze_email_message(service, message)
                for row in legacy_stream_rows(analyzed):
                    yield f"data: {json.dumps(row)}\n\n"
            except Exception as exc:
                error_row = {
                    "sender": "Unknown",
                    "domain_name": "Analysis Error",
                    "nlp_label": "ERROR",
                    "phish_score": 0,
                    "verdict": f"Error: {exc}",
                }
                yield f"data: {json.dumps(error_row)}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@app.route("/analyze-text", methods=["POST"])
def analyze_text() -> Any:
    try:
        payload = request.get_json(force=True) or {}
        text = payload.get("content", "")
        sender = payload.get("sender", "User")
        analysis = build_analysis_result(text=text, sender=sender)
        verdict = verdict_from_risk(int(analysis["risk_score"]))
        result_item = {
            "verdict": verdict,
            "phish_score": int(analysis["risk_score"]),
            "probability_score": int(analysis["confidence"]),
        }
        response = {
            "nlp": {
                "verdict": analysis["verdict"],
                "label": analysis["verdict"],
                "score": int(analysis["text_score"]),
                "reason": analysis["reasoning"][0] if analysis["reasoning"] else "No strong phishing indicators detected",
            },
            "results": [result_item],
            "phishing_detected": analysis["verdict"] == "PHISHING",
            **analysis,
        }
        add_history(
            history_item(
                unique_key=f"sms_bot:{datetime.now(timezone.utc).isoformat()}",
                source_type="sms_bot",
                sender=sender,
                message_text=text,
                verdict=verdict,
                phish_score=int(analysis["risk_score"]),
                nlp_label=response["nlp"]["verdict"],
                reasons=analysis["reasoning"],
                details=response,
            )
        )
        return jsonify(response)
    except Exception as exc:
        return jsonify({"error": f"Text analysis failed safely: {exc}"}), 500


@app.route("/get-history")
def get_history() -> Any:
    load_history_from_db()
    return jsonify(ANALYSIS_HISTORY)


init_archive_db()
load_history_from_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
