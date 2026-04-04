#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import whois
import json
import tempfile
import secrets
import time
from html import unescape
from pathlib import Path
from datetime import datetime, date, timedelta
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, Tuple, Dict, Any, List
from difflib import SequenceMatcher

from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, Response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, inspect

# Google Auth Libraries
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from oauthlib.oauth2.rfc6749.errors import MismatchingStateError

# Hugging Face Integration
from transformers import pipeline

# Audio processing
try:
    import speech_recognition as sr
except Exception:
    sr = None

try:
    from pydub import AudioSegment
except Exception:
    AudioSegment = None

import io

try:
    from langdetect import detect, LangDetectException
except Exception:
    detect = None
    LangDetectException = Exception

try:
    from deep_translator import GoogleTranslator
except Exception:
    GoogleTranslator = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except Exception:
    sync_playwright = None
    PlaywrightTimeoutError = Exception

try:
    from selenium import webdriver
    from selenium.common.exceptions import TimeoutException as SeleniumTimeoutException, WebDriverException
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.edge.options import Options as EdgeOptions
except Exception:
    webdriver = None
    SeleniumTimeoutException = Exception
    WebDriverException = Exception
    ChromeOptions = None
    EdgeOptions = None
    By = None

import requests

app = Flask(__name__)
app.secret_key = "phishguard_secure_dev_key_123"
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
CORS(app)

GMAIL_CONNECTIONS = {}
GOOGLE_CLIENT_SECRET_PATH = Path(__file__).resolve().parent / "client_secret.json"

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

def load_google_web_config() -> Dict[str, Any]:
    try:
        with GOOGLE_CLIENT_SECRET_PATH.open("r", encoding="utf-8") as fh:
            return json.load(fh).get("web", {})
    except Exception:
        return {}


def get_google_redirect_uri(current_host_url: Optional[str] = None) -> str:
    redirect_uris = load_google_web_config().get("redirect_uris", [])
    if redirect_uris:
        if current_host_url:
            current_origin = current_host_url.rstrip("/")
            for redirect_uri in redirect_uris:
                if redirect_uri.startswith(current_origin):
                    return redirect_uri
        return redirect_uris[0]
    return "http://127.0.0.1:5000/callback"

# --- ENHANCED SCAM KEYWORD DATABASE ---
SCAM_KEYWORDS = {
    'urgent': 15, 'immediate': 12, 'verify': 8, 'account': 10,
    'suspended': 18, 'locked': 15, 'security': 12, 'alert': 10,
    'update': 8, 'confirm': 10, 'information': 8, 'password': 15,
    'social security': 20, 'bank account': 18, 'credit card': 15,
    'wire transfer': 18, 'western union': 20, 'gift card': 20,
    'itunes card': 20, 'google play card': 18, 'cryptocurrency': 15,
    'bitcoin': 15, 'payment': 10, 'invoice': 10, 'refund': 12,
    'lottery': 20, 'prize': 15, 'won': 12, 'free': 8,
    'limited time': 12, 'expires': 10, 'deadline': 12,
    'irs': 20, 'tax': 15, 'police': 18, 'legal action': 20,
    'lawsuit': 18, 'arrest': 20, 'warrant': 20, 'court': 15,
    'microsoft': 10, 'apple': 10, 'paypal': 12, 'amazon': 10,
    'netflix': 10, 'bank': 15, 'chase': 12, 'wells fargo': 12,
    'click here': 10, 'link below': 8, 'attachment': 10,
    'login': 8, 'sign in': 8, 'credentials': 15, 'username': 10,
    'unusual activity': 18, 'suspicious activity': 18,
    'unauthorized': 15, 'fraud': 20, 'scam': 20, 'phishing': 20,
    'otp': 35, 'kyc': 32, 'upi': 30, 'received money': 32,
    'claim now': 30, 'click here to claim': 38
}

STRONG_SCAM_INDICATORS = {
    'otp': 35,
    'one time password': 35,
    'bank account': 30,
    'verify now': 30,
    'urgent': 25,
    'kyc': 32,
    'card blocked': 35,
    'transfer money': 35,
    'reward claim': 30,
    'lottery': 32,
    'suspend': 28,
    'penalty': 28,
    'account suspended': 35,
    'click link': 25,
    'remote access': 35,
    'gift card': 32,
    'refund processing': 28,
    'claim reward': 28,
    'verify your account': 30,
    'click here to claim': 38,
    'claim now': 30,
    'upi': 30,
    'received money': 32,
    'cashback': 28,
    'claim': 25,
    'click here': 22,
    'fake-upi': 40,
    'free money': 35,
    'you have received': 28,
    'won': 30,
    'winner': 30,
    'prize': 28
}

# --- NLP Model Initialization ---
print("Loading Phishing Detection Models...")
try:
    spam_classifier = pipeline(
        "text-classification",
        model="mrm8488/bert-tiny-finetuned-sms-spam-detection"
    )
    print("Spam detection model loaded!")
except Exception as e:
    print(f"Error loading model: {e}")
    spam_classifier = None

# Sentiment analysis
try:
    sentiment_analyzer = pipeline(
        "sentiment-analysis",
        model="distilbert-base-uncased-finetuned-sst-2-english"
    )
    print("Sentiment analyzer loaded!")
except Exception as e:
    print(f"Sentiment analyzer not available: {e}")
    sentiment_analyzer = None

# --- TRUSTED DOMAINS ---
TRUSTED_DOMAINS = [
    'google.com', 'microsoft.com', 'mongodb.com', 'upwork.com',
    'github.com', 'linkedin.com', 'firebase.com', 'stanford.edu',
    'apple.com', 'amazon.com', 'netflix.com', 'facebook.com',
    'coursera.org', 'alibaba.com', 'dribbble.com', 'quora.com',
    'et-ai.com', 'freelancer.com', 'zoom.us', 'slack.com', 'trello.com',
    'paypal.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    'capitalone.com', 'citibank.com', 'usbank.com', 'td.com',
    'hackthecore.com', 'hackthecore.in'
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online', '.site', '.website', '.space', '.tech', '.store']
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 't.co', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'rebrand.ly']
FREE_HOSTING_DOMAINS = ['000webhostapp.com', 'weebly.com', 'wixsite.com', 'blogspot.com', 'pages.dev', 'github.io', 'netlify.app', 'vercel.app', 'web.app', 'firebaseapp.com', 'glitch.me', 'replit.app']
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9"
}

TRUSTED_BRAND_MAP = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "linkedin": "linkedin.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "github": "github.com",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "capital one": "capitalone.com",
    "citibank": "citibank.com",
    "slack": "slack.com",
    "zoom": "zoom.us",
    "coursera": "coursera.org",
}

# --- Database Setup ---
BASE_DIR = Path(__file__).resolve().parent
SANDBOX_SCREENSHOT_DIR = BASE_DIR / "sandbox_previews"
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    f"sqlite:///{(BASE_DIR / 'phishguard.db').as_posix()}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class ThreatHistory(db.Model):
    __tablename__ = 'threat_history'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, server_default=text('CURRENT_TIMESTAMP'))
    source_type = db.Column(db.String(50), nullable=False)
    sender = db.Column(db.String(255))
    message_text = db.Column(db.Text)
    detected_url = db.Column(db.Text)
    domain_name = db.Column(db.String(255))
    domain_age_days = db.Column(db.Integer)
    has_ssl = db.Column(db.Boolean)
    nlp_label = db.Column(db.String(50))
    phish_score = db.Column(db.Integer)
    verdict = db.Column(db.String(50))
    audio_transcript = db.Column(db.Text)
    scam_indicators = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "N/A",
            "sender": self.sender,
            "message_text": self.message_text,
            "source_type": self.source_type,
            "detected_url": self.detected_url,
            "domain_name": self.domain_name,
            "domain_age_days": self.domain_age_days,
            "has_ssl": self.has_ssl,
            "nlp_label": self.nlp_label,
            "phish_score": self.phish_score,
            "verdict": self.verdict,
            "audio_transcript": self.audio_transcript,
            "scam_indicators": self.scam_indicators
        }

def save_history_entry(
    source_type: str,
    sender: str,
    message_text: str = "",
    detected_url: str = "",
    domain_name: str = "",
    domain_age_days: Optional[int] = None,
    has_ssl: Optional[bool] = None,
    nlp_label: str = "",
    phish_score: int = 0,
    verdict: str = "Safe",
    audio_transcript: Optional[str] = None,
    scam_indicators: Optional[List[str]] = None,
    commit: bool = True
):
    entry = ThreatHistory(
        source_type=source_type,
        sender=sender,
        message_text=message_text,
        detected_url=detected_url,
        domain_name=domain_name,
        domain_age_days=domain_age_days,
        has_ssl=has_ssl,
        nlp_label=nlp_label,
        phish_score=phish_score,
        verdict=verdict,
        audio_transcript=audio_transcript,
        scam_indicators=json.dumps(scam_indicators or [])
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry

with app.app_context():
    db.create_all()

# --- Helper Functions ---

def extract_urls(text):
    return re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)

def is_public_ip(ip_value: str) -> bool:
    try:
        octets = [int(part) for part in ip_value.split('.')]
        if len(octets) != 4 or any(part < 0 or part > 255 for part in octets):
            return False
        if octets[0] in {10, 127}:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 169 and octets[1] == 254:
            return False
        return True
    except Exception:
        return False

def extract_sender_ip_from_headers(headers: List[Dict[str, str]]) -> Optional[str]:
    candidate_headers = []
    originating = next((h.get('value', '') for h in headers if h.get('name', '').lower() == 'x-originating-ip'), '')
    if originating:
        candidate_headers.append(originating)
    candidate_headers.extend([h.get('value', '') for h in headers if h.get('name', '').lower() == 'received'])
    for header_value in candidate_headers:
        matches = re.findall(r'(?:\b|\[)(\d{1,3}(?:\.\d{1,3}){3})(?:\b|\])', header_value or '')
        for match in matches:
            if is_public_ip(match):
                return match
    return None

def lookup_ip_geolocation(ip_value: Optional[str]) -> Dict[str, Any]:
    if not ip_value:
        return {
            "sender_ip": None,
            "actual_location": "Unknown",
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "org": None,
            "error": "No public sender IP detected"
        }
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_value}",
            params={"fields": "status,message,country,regionName,city,isp,org,query"},
            timeout=6,
            headers=REQUEST_HEADERS
        )
        data = response.json() if response.ok else {}
        if data.get("status") == "success":
            actual_location = ", ".join(part for part in [data.get("city"), data.get("regionName"), data.get("country")] if part) or "Unknown"
            return {
                "sender_ip": data.get("query") or ip_value,
                "actual_location": actual_location,
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "error": None
            }
        return {
            "sender_ip": ip_value,
            "actual_location": "Unknown",
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "org": None,
            "error": data.get("message") or "Geo lookup failed"
        }
    except Exception as exc:
        return {
            "sender_ip": ip_value,
            "actual_location": "Unknown",
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "org": None,
            "error": str(exc)
        }

def flatten_gmail_parts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    flattened = []
    stack = [payload] if payload else []
    while stack:
        part = stack.pop()
        flattened.append(part)
        for child in part.get("parts", []) or []:
            stack.append(child)
    return flattened

def summarize_gmail_attachments(payload: Dict[str, Any]) -> Dict[str, Any]:
    files = []
    for part in flatten_gmail_parts(payload):
        filename = (part.get("filename") or "").strip()
        body = part.get("body") or {}
        if filename or body.get("attachmentId"):
            files.append({
                "file_name": filename or "unnamed attachment",
                "mime_type": part.get("mimeType") or "unknown",
                "size": body.get("size", 0)
            })
    mime_groups = {}
    total_size = 0
    for item in files:
        mime_groups[item["mime_type"]] = mime_groups.get(item["mime_type"], 0) + 1
        total_size += int(item.get("size", 0) or 0)
    return {
        "count": len(files),
        "files": files[:8],
        "mime_groups": mime_groups,
        "total_size": total_size
    }

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, str):
            creation_date = creation_date.split('T')[0].split(' ')[0]
            creation_date = datetime.fromisoformat(creation_date)
        elif isinstance(creation_date, date) and not isinstance(creation_date, datetime):
            creation_date = datetime.combine(creation_date, datetime.min.time())
        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            return max(0, (datetime.utcnow() - creation_date).days)
        return None
    except:
        return None

def clean_transcript_text(text_value: str) -> str:
    if not text_value:
        return ""
    text_value = re.sub(r'\s+', ' ', text_value).strip()
    text_value = re.sub(r'\b([A-Za-z])(?:\s+\1){2,}\b', r'\1', text_value)
    text_value = re.sub(r'([!?.,])\1{2,}', r'\1', text_value)
    return text_value

def detect_language_label(text_value: str) -> str:
    if not text_value:
        return "unknown"
    devanagari_chars = re.findall(r'[\u0900-\u097F]', text_value)
    if len(devanagari_chars) >= 3:
        return "hi"
    lowered = text_value.lower()
    hinglish_markers = [
        'aap', 'namaste', 'kripya', 'jaldi', 'turant', 'paisa',
        'bhejo', 'karo', 'mat', 'nahi', 'hai', 'apka', 'aapka'
    ]
    if any(marker in lowered for marker in hinglish_markers):
        return "hinglish"
    if detect:
        try:
            detected = detect(text_value)
            if detected and detected != 'unknown':
                return detected
        except:
            pass
    ascii_ratio = sum(1 for ch in text_value if ord(ch) < 128) / max(len(text_value), 1)
    if ascii_ratio > 0.85:
        return "en"
    return "unknown"

def translate_to_english(text_value: str, language: str) -> Tuple[str, bool, Optional[str]]:
    if not text_value or language in ('en', 'hinglish'):
        return text_value, False, None
    if GoogleTranslator:
        try:
            translated = GoogleTranslator(source='auto', target='en').translate(text_value)
            return translated, True, None
        except Exception as e:
            return text_value, False, str(e)
    return text_value, False, None

def humanize_age_days(days: Optional[int]) -> str:
    if days is None:
        return "Unknown"
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''}"
    months = round(days / 30)
    if days < 365:
        return f"{months} month{'s' if months != 1 else ''}"
    years = round(days / 365, 1)
    return f"{years} year{'s' if years != 1 else ''}"

def clean_text_block(value: str, limit: int = 260) -> str:
    value = clean_transcript_text(unescape(value or ""))
    return value[:limit]

def decode_duckduckgo_result(url: str) -> str:
    try:
        parsed = urlparse(url)
        if "duckduckgo.com" in parsed.netloc:
            uddg = parse_qs(parsed.query).get("uddg")
            if uddg:
                return unquote(uddg[0])
        return url
    except Exception:
        return url

def fetch_url(url: str, timeout: int = 12) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        response = requests.get(url, timeout=timeout, headers=REQUEST_HEADERS, allow_redirects=True)
        return response, None
    except Exception as exc:
        return None, str(exc)

def extract_company_hints(text_value: str) -> List[str]:
    if not text_value:
        return []
    stopwords = {
        'linkedin', 'jobs', 'job', 'careers', 'career', 'apply', 'remote', 'work',
        'full', 'time', 'contract', 'page', 'view', 'www', 'https', 'http'
    }
    hints = []
    for token in re.findall(r'[A-Za-z][A-Za-z&.-]{2,}', text_value):
        token = token.strip("-._")
        lowered = token.lower()
        if lowered in stopwords:
            continue
        if token[0].isupper() or lowered not in stopwords:
            hints.append(token)
    seen = []
    for hint in hints:
        if hint.lower() not in [x.lower() for x in seen]:
            seen.append(hint)
    return seen[:6]

def search_web(query: str, limit: int = 6) -> List[Dict[str, str]]:
    results = []
    try:
        response = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            timeout=12,
            headers=REQUEST_HEADERS
        )
        if not response.ok or not BeautifulSoup:
            return results
        soup = BeautifulSoup(response.text, "html.parser")
        for block in soup.select(".result")[:limit]:
            link_tag = block.select_one(".result__a")
            if not link_tag:
                continue
            snippet_tag = block.select_one(".result__snippet")
            href = decode_duckduckgo_result(link_tag.get("href", ""))
            results.append({
                "title": clean_text_block(link_tag.get_text(" ", strip=True), 120),
                "url": href,
                "snippet": clean_text_block(snippet_tag.get_text(" ", strip=True) if snippet_tag else "", 200)
            })
        return results
    except Exception:
        return results

def build_targeting_profile(text_value: str) -> Dict[str, Any]:
    lowered = (text_value or "").lower()
    hooks = []
    target_traits = []
    delivery_style = []

    rule_map = [
        (['otp', 'verify', 'kyc', 'password', 'login', 'account'], 'credential theft', 'user with active banking or platform accounts', 'identity/account pressure'),
        (['reward', 'cashback', 'winner', 'claim', 'prize', 'bonus'], 'reward bait', 'deal-seeking or reward-responsive user', 'impulse/reward trigger'),
        (['upi', 'transfer', 'payment', 'received', 'refund', 'bank account'], 'money movement', 'user expected to react to payment alerts', 'financial urgency'),
        (['courier', 'delivery', 'shipment', 'tracking', 'order'], 'delivery pretext', 'online shopper or recent buyer', 'context hijack'),
        (['blocked', 'suspend', 'penalty', 'urgent', 'final warning'], 'fear escalation', 'user likely to comply under pressure', 'threat/escalation')
    ]

    for terms, hook, target_trait, style in rule_map:
        if any(term in lowered for term in terms):
            hooks.append(hook)
            target_traits.append(target_trait)
            delivery_style.append(style)

    if any(ch.isdigit() for ch in text_value or ""):
        delivery_style.append("automation-friendly formatting")
    if re.search(r'https?://|bit\.ly|tinyurl', lowered):
        delivery_style.append("click-through funnel")

    hooks = list(dict.fromkeys(hooks))
    target_traits = list(dict.fromkeys(target_traits))
    delivery_style = list(dict.fromkeys(delivery_style))

    if not hooks:
        hooks = ["generic social engineering"]
    if not target_traits:
        target_traits = ["broad consumer audience"]
    if not delivery_style:
        delivery_style = ["generic persuasion pattern"]

    summary = (
        f"The message appears built around {', '.join(hooks[:2])}, aimed at a "
        f"{target_traits[0]}, and delivered using {', '.join(delivery_style[:2])}."
    )

    return {
        "hooks": hooks[:4],
        "target_traits": target_traits[:4],
        "delivery_style": delivery_style[:4],
        "summary": summary
    }

def fetch_website_content(url: str) -> Dict[str, Any]:
    result = {
        "final_url": url,
        "redirect_chain": [],
        "status_code": None,
        "title": None,
        "content_text": "",
        "safe_preview": None,
        "error": None
    }
    try:
        response = requests.get(url, timeout=12, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["redirect_chain"] = [resp.url for resp in response.history] + [response.url]
        if "text/html" in response.headers.get("Content-Type", ""):
            html = response.text[:200000]
            if BeautifulSoup:
                soup = BeautifulSoup(html, "html.parser")
                result["title"] = soup.title.get_text(" ", strip=True) if soup.title else None
                result["content_text"] = clean_transcript_text(soup.get_text(" ", strip=True))[:5000]
                result["safe_preview"] = build_safe_website_preview(soup, response.url)
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

def build_safe_website_preview(soup: Any, source_url: str) -> Dict[str, Any]:
    working = BeautifulSoup(str(soup), "html.parser") if BeautifulSoup else None
    if not working:
        return {
            "title": "Preview unavailable",
            "html": "<div>Preview unavailable</div>",
            "has_login_form": False,
            "suspicious": False,
            "reason": "HTML parser unavailable."
        }

    title = working.title.get_text(" ", strip=True) if working.title else "Website preview"
    page_text = clean_transcript_text(working.get_text(" ", strip=True))[:1200]
    lowered = page_text.lower()
    has_login_form = any(term in lowered for term in ["sign in", "log in", "password", "otp", "verification code"])
    suspicious = has_login_form or any(term in lowered for term in ["verify account", "claim reward", "urgent action", "bank account"])
    reason = (
        "Login or credential language detected in the fetched page."
        if has_login_form else
        "Sensitive action phrases detected in the fetched page."
        if suspicious else
        "Static preview generated with scripts, forms, and external resources removed."
    )

    for tag_name in ["script", "style", "iframe", "frame", "object", "embed", "link", "meta", "noscript", "svg", "canvas"]:
        for tag in working.find_all(tag_name):
            tag.decompose()

    for form in working.find_all("form"):
        replacement = working.new_tag("div")
        replacement["class"] = "pg-card pg-warning"
        replacement.string = "Interactive form removed for safe preview."
        form.replace_with(replacement)

    for tag in working.find_all(True):
        attrs_to_remove = []
        for attr_name in list(tag.attrs.keys()):
            lowered_attr = attr_name.lower()
            if lowered_attr.startswith("on") or lowered_attr in {"src", "srcset", "href", "action", "poster", "data", "integrity", "crossorigin"}:
                attrs_to_remove.append(attr_name)
        for attr_name in attrs_to_remove:
            tag.attrs.pop(attr_name, None)
        if tag.name in {"input", "button", "select", "textarea", "option"}:
            replacement = working.new_tag("span")
            replacement["class"] = "pg-chip"
            replacement.string = f"{tag.name.title()} removed"
            tag.replace_with(replacement)
            continue
        tag.attrs["tabindex"] = "-1"

    preview_root = working.body or working
    preview_html = str(preview_root)[:35000]
    sandbox_html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{
    margin: 0;
    padding: 20px;
    background: linear-gradient(180deg, #07111a 0%, #0f172a 100%);
    color: #e2e8f0;
    font-family: 'Segoe UI', Arial, sans-serif;
}}
* {{
    max-width: 100%;
    box-sizing: border-box;
    pointer-events: none !important;
}}
a {{ color: #7dd3fc; text-decoration: none; }}
img {{ display: none !important; }}
.pg-banner {{
    margin-bottom: 16px;
    padding: 12px 14px;
    border-radius: 14px;
    border: 1px solid rgba(125, 211, 252, 0.25);
    background: rgba(15, 23, 42, 0.88);
    color: #cbd5e1;
    font-size: 12px;
}}
.pg-card {{
    padding: 12px 14px;
    border-radius: 14px;
    background: rgba(30, 41, 59, 0.65);
    border: 1px dashed rgba(248, 113, 113, 0.35);
    color: #fecaca;
    margin: 10px 0;
}}
.pg-warning {{
    border-style: solid;
}}
.pg-chip {{
    display: inline-block;
    padding: 6px 10px;
    margin: 4px;
    border-radius: 999px;
    background: rgba(148, 163, 184, 0.18);
    color: #e2e8f0;
    font-size: 12px;
}}
</style>
</head>
<body>
    <div class="pg-banner">Safe preview sandbox. Remote scripts, forms, links, and media loads are disabled. Source: {clean_text_block(source_url, 200)}</div>
    {preview_html}
</body>
</html>"""

    return {
        "title": title,
        "html": sandbox_html,
        "text_excerpt": page_text[:500],
        "has_login_form": has_login_form,
        "suspicious": suspicious,
        "reason": reason
    }

def normalize_domain(domain: str) -> str:
    domain = (domain or "").lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def get_registered_domain(domain: str) -> str:
    domain = normalize_domain(domain)
    parts = [part for part in domain.split('.') if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            insertions = prev[j] + 1
            deletions = curr[j - 1] + 1
            substitutions = prev[j - 1] + (ca != cb)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]

def check_domain_impersonation(domain: str) -> Optional[Dict[str, Any]]:
    registered = get_registered_domain(domain)
    base = registered.split('.')[0]
    
    # First check if domain is in trusted list
    if registered in TRUSTED_DOMAINS or domain in TRUSTED_DOMAINS:
        return {"matched_brand": registered, "is_impersonating": False, "reason": "Domain matches trusted brand."}
    
    best_match = None
    best_distance = 999
    
    for trusted in TRUSTED_DOMAINS:
        trusted_registered = get_registered_domain(trusted)
        trusted_base = trusted_registered.split('.')[0]
        distance = levenshtein_distance(base, trusted_base)
        
        # Only consider matches that are close enough
        if distance < best_distance and distance <= 3:
            best_match = trusted_registered
            best_distance = distance
    
    if not best_match:
        return {"matched_brand": None, "is_impersonating": False, "reason": "No brand match found"}
    
    if registered == best_match:
        return {"matched_brand": best_match, "is_impersonating": False, "reason": "Domain matches trusted brand."}
    
    if best_distance <= 2:
        return {"matched_brand": best_match, "is_impersonating": True, "reason": f"Looks similar to {best_match}."}
    
    return {"matched_brand": None, "is_impersonating": False, "reason": "No brand match found"}

def check_url_safety(url: str) -> List[str]:
    domain = urlparse(url).netloc or url.split("//")[-1].split("/")[0]
    threats = []
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            threats.append(f"Suspicious TLD: {tld}")
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            threats.append(f"URL shortener: {shortener}")
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        threats.append("IP address used")
    return threats

def classify_verdict(score: int) -> str:
    if score >= 70:
        return "Malicious"
    if score >= 40:
        return "Suspicious"
    return "Safe"

def quick_gmail_scan_analysis(text_content: str) -> Dict[str, Any]:
    cleaned_text = clean_transcript_text(text_content or "")
    lowered = cleaned_text.lower()
    if not lowered:
        return {
            "label": "SAFE",
            "score": 0,
            "reason": "No content",
            "indicators": [],
            "keyword_hits": [],
            "tone": "Neutral",
            "language": "unknown"
        }

    keyword_hits = []
    score = 0
    for keyword, weight in SCAM_KEYWORDS.items():
        if keyword in lowered:
            keyword_hits.append(keyword)
            score += min(weight, 14)

    strong_hits = []
    for keyword, weight in STRONG_SCAM_INDICATORS.items():
        if keyword in lowered:
            strong_hits.append(keyword)
            score += min(weight, 22)

    urls = extract_urls(cleaned_text)
    suspicion_reasons = []
    if urls:
        score += 12
        suspicion_reasons.append("Contains a clickable URL, which can redirect to an external site")
    if any(term in lowered for term in ['login', 'sign in', 'verify', 'otp', 'kyc', 'password']):
        score += 18
        suspicion_reasons.append("Requests account verification, login credentials, password, OTP, or KYC action")
    if any(term in lowered for term in ['claim', 'reward', 'winner', 'prize', 'cashback']):
        score += 18
        suspicion_reasons.append("Uses reward, prize, cashback, or winner-style bait language")
    if any(term in lowered for term in ['invoice', 'payment', 'bank', 'upi', 'refund']):
        score += 16
        suspicion_reasons.append("References money, banking, refunds, invoices, or payment pressure")
    if any(term in lowered for term in ['urgent', 'immediately', 'final warning', 'act now']):
        score += 14
        suspicion_reasons.append("Uses urgency pressure to push immediate action")

    final_score = min(100, score)
    if urls and strong_hits:
        final_score = max(final_score, 68)
    if len(strong_hits) >= 2:
        final_score = max(final_score, 78)

    if strong_hits:
        suspicion_reasons.append("Contains multiple high-risk phishing keywords commonly seen in scams")

    if not suspicion_reasons and keyword_hits:
        suspicion_reasons.append("Contains suspicious terms often associated with phishing or scam campaigns")

    deduped_reasons = []
    seen_reasons = set()
    for reason in suspicion_reasons:
        normalized = reason.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen_reasons:
            continue
        seen_reasons.add(key)
        deduped_reasons.append(normalized)

    tone = "Urgent" if any(term in lowered for term in ['urgent', 'immediately', 'act now']) else "Neutral"
    return {
        "label": "SCAM" if final_score > 50 else "SAFE",
        "score": final_score,
        "reason": deduped_reasons[0] if deduped_reasons else "",
        "indicators": deduped_reasons[:4],
        "keyword_hits": (strong_hits + keyword_hits)[:8],
        "tone": tone,
        "language": "unknown"
    }

def extract_brand_mentions(text_value: str) -> List[str]:
    lowered = (text_value or "").lower()
    mentions = [brand for brand in TRUSTED_BRAND_MAP if brand in lowered]
    return mentions[:8]

def detect_domain_brand_mismatch(brand_names: List[str], final_domain: str) -> bool:
    registered_domain = get_registered_domain(final_domain)
    for brand in brand_names:
        trusted_domain = TRUSTED_BRAND_MAP.get(brand)
        if trusted_domain and registered_domain != trusted_domain:
            return True
    return False

def infer_sandbox_risk_level(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"

def detect_possible_js_redirect(html: str, original_url: str, final_url: str, redirect_chain: List[str]) -> bool:
    lowered_html = (html or "").lower()
    js_markers = [
        "window.location",
        "location.href",
        "location.replace",
        "document.location",
        "http-equiv=\"refresh\"",
        "http-equiv='refresh'",
        "url="
    ]
    has_marker = any(marker in lowered_html for marker in js_markers)
    return bool(has_marker and final_url and final_url != original_url and len(redirect_chain) <= 2)

def analyze_dynamic_page_snapshot(
    original_url: str,
    final_url: str,
    redirect_chain: List[str],
    html: str,
    page_text: str,
    screenshot_path: Optional[str] = None
) -> Dict[str, Any]:
    result = {
        "sandbox_score": 0,
        "risk_level": "Low",
        "behaviors": [],
        "redirect_chain": redirect_chain or [original_url],
        "final_url": final_url or original_url,
        "forms_detected": {
            "login_form": False,
            "password_field": False,
            "otp_field": False
        },
        "page_signals": {
            "brand_names": [],
            "suspicious_cta": [],
            "domain_brand_mismatch": False
        },
        "errors": []
    }
    if screenshot_path:
        result["screenshot_path"] = screenshot_path

    soup = BeautifulSoup(html, "html.parser") if BeautifulSoup and html else None
    lowered_text = (page_text or "").lower()
    all_cta_text = []
    suspicious_keywords = ["verify", "claim", "continue", "login", "sign in", "download", "reward", "urgent", "bank", "kyc"]

    if soup:
        password_inputs = soup.select("input[type='password']")
        otp_inputs = soup.select(
            "input[name*='otp' i], input[id*='otp' i], input[name*='pin' i], input[id*='pin' i], "
            "input[name*='code' i], input[id*='code' i], input[autocomplete='one-time-code']"
        )
        login_forms = soup.select("form")
        result["forms_detected"]["password_field"] = bool(password_inputs)
        result["forms_detected"]["otp_field"] = bool(otp_inputs)
        result["forms_detected"]["login_form"] = bool(password_inputs)

        for form in login_forms:
            form_text = clean_transcript_text(form.get_text(" ", strip=True)).lower()
            if any(term in form_text for term in ["login", "sign in", "verify", "password", "email"]):
                result["forms_detected"]["login_form"] = True
                break

        interactive_nodes = soup.select("a, button, input[type='submit'], input[type='button']")
        for node in interactive_nodes:
            node_text = clean_transcript_text(
                " ".join(filter(None, [
                    node.get_text(" ", strip=True),
                    node.get("value", ""),
                    node.get("aria-label", "")
                ]))
            ).lower()
            if node_text:
                all_cta_text.append(node_text)

        download_trigger = any(
            ("download" in text_value or "install" in text_value) for text_value in all_cta_text
        ) or any(
            (node.get("href", "") or "").lower().endswith(ext)
            for node in interactive_nodes
            for ext in [".exe", ".msi", ".apk", ".zip", ".scr"]
        )
    else:
        download_trigger = False

    suspicious_cta = []
    search_space = " ".join(all_cta_text) + " " + lowered_text
    for keyword in suspicious_keywords:
        if keyword in search_space and keyword not in suspicious_cta:
            suspicious_cta.append(keyword)

    brand_names = extract_brand_mentions(page_text)
    domain_brand_mismatch = detect_domain_brand_mismatch(brand_names, final_url or original_url)
    js_redirect = detect_possible_js_redirect(html, original_url, final_url, redirect_chain)

    score = 0
    behaviors = []
    redirect_count = max(0, len((redirect_chain or [])) - 1)
    if redirect_count > 2:
        score += 20
        behaviors.append(f"Multiple redirects observed ({redirect_count})")
    if js_redirect:
        score += 20
        behaviors.append("Possible client-side/JavaScript redirect detected")
    if result["forms_detected"]["login_form"] or result["forms_detected"]["password_field"]:
        score += 25
        behaviors.append("Login credential collection form detected")
    if result["forms_detected"]["otp_field"]:
        score += 30
        behaviors.append("OTP/code/PIN collection field detected")
    if suspicious_cta:
        cta_score = min(45, len(suspicious_cta) * 15)
        score += cta_score
        behaviors.append(f"Suspicious CTA phrases detected: {', '.join(suspicious_cta)}")
    if domain_brand_mismatch:
        score += 30
        behaviors.append("Page brand mentions do not match the hosting domain")
    if download_trigger:
        score += 25
        behaviors.append("Suspicious download/install trigger detected")

    score = min(100, score)
    result["sandbox_score"] = score
    result["risk_level"] = infer_sandbox_risk_level(score)
    result["behaviors"] = behaviors
    result["page_signals"]["brand_names"] = brand_names
    result["page_signals"]["suspicious_cta"] = suspicious_cta
    result["page_signals"]["domain_brand_mismatch"] = domain_brand_mismatch
    return result

def build_selenium_driver():
    if not webdriver:
        raise RuntimeError("Selenium is not installed.")
    driver_errors = []
    if EdgeOptions:
        try:
            edge_options = EdgeOptions()
            edge_options.add_argument("--headless=new")
            edge_options.add_argument("--disable-gpu")
            edge_options.add_argument("--no-sandbox")
            edge_options.add_argument("--disable-dev-shm-usage")
            edge_options.add_argument("--ignore-certificate-errors")
            edge_options.add_argument("--window-size=1440,1800")
            driver = webdriver.Edge(options=edge_options)
            driver.set_page_load_timeout(20)
            return driver
        except Exception as exc:
            driver_errors.append(f"Edge: {exc}")
    if ChromeOptions:
        try:
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--window-size=1440,1800")
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(20)
            return driver
        except Exception as exc:
            driver_errors.append(f"Chrome: {exc}")
    raise RuntimeError(" ; ".join(driver_errors) or "No Selenium browser driver available.")

def save_sandbox_screenshot_blob(filename_prefix: str, png_bytes: bytes) -> Optional[str]:
    try:
        SANDBOX_SCREENSHOT_DIR.mkdir(exist_ok=True)
        filename = f"{filename_prefix}_{int(time.time())}.png"
        output_path = SANDBOX_SCREENSHOT_DIR / filename
        output_path.write_bytes(png_bytes)
        return f"/sandbox-preview-image/{filename}"
    except Exception:
        return None

def save_sandbox_screenshot_from_driver(filename_prefix: str, driver: Any) -> Optional[str]:
    try:
        SANDBOX_SCREENSHOT_DIR.mkdir(exist_ok=True)
        filename = f"{filename_prefix}_{int(time.time())}.png"
        output_path = SANDBOX_SCREENSHOT_DIR / filename
        driver.save_screenshot(str(output_path))
        return f"/sandbox-preview-image/{filename}"
    except Exception:
        return None

def dynamic_sandbox_analyze_url(url: str) -> Dict[str, Any]:
    normalized_url = url.strip()
    if not re.match(r'^https?://', normalized_url, re.I):
        normalized_url = f"https://{normalized_url}"

    empty_result = {
        "sandbox_score": 0,
        "risk_level": "Low",
        "behaviors": [],
        "redirect_chain": [normalized_url],
        "final_url": normalized_url,
        "forms_detected": {
            "login_form": False,
            "password_field": False,
            "otp_field": False
        },
        "page_signals": {
            "brand_names": [],
            "suspicious_cta": [],
            "domain_brand_mismatch": False
        },
        "errors": []
    }

    if sync_playwright:
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_default_timeout(15000)
                response = page.goto(normalized_url, wait_until="domcontentloaded")
                page.wait_for_timeout(1800)
                final_url = page.url
                redirect_chain = []
                if response:
                    request_chain = response.request
                    while request_chain:
                        redirect_chain.append(request_chain.url)
                        request_chain = request_chain.redirected_from
                    redirect_chain = list(reversed(redirect_chain))
                if not redirect_chain:
                    redirect_chain = [normalized_url]
                if final_url and final_url != redirect_chain[-1]:
                    redirect_chain.append(final_url)
                html = page.content()
                page_text = page.evaluate("() => document.body ? document.body.innerText : ''")
                screenshot_path = None
                try:
                    screenshot_bytes = page.screenshot(full_page=True, timeout=5000)
                    screenshot_path = save_sandbox_screenshot_blob("playwright_preview", screenshot_bytes)
                except Exception:
                    screenshot_path = None
                browser.close()
                result = analyze_dynamic_page_snapshot(
                    normalized_url,
                    final_url,
                    redirect_chain,
                    html,
                    page_text,
                    screenshot_path=screenshot_path
                )
                result["engine"] = "playwright"
                return result
        except Exception as exc:
            empty_result["errors"].append(f"Playwright failed: {exc}")

    if webdriver:
        driver = None
        try:
            driver = build_selenium_driver()
            driver.get(normalized_url)
            time.sleep(2)
            final_url = driver.current_url
            redirect_chain = [normalized_url]
            if final_url and final_url != normalized_url:
                redirect_chain.append(final_url)
            html = driver.page_source
            page_text = ""
            try:
                page_text = driver.find_element(By.TAG_NAME, "body").text if By else ""
            except Exception:
                page_text = ""
            screenshot_path = save_sandbox_screenshot_from_driver("selenium_preview", driver)
            result = analyze_dynamic_page_snapshot(
                normalized_url,
                final_url,
                redirect_chain,
                html,
                page_text,
                screenshot_path=screenshot_path
            )
            result["engine"] = "selenium"
            result["errors"].extend(empty_result["errors"])
            return result
        except Exception as exc:
            empty_result["errors"].append(f"Selenium failed: {exc}")
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    if not empty_result["errors"]:
        empty_result["errors"].append("Dynamic sandbox engine unavailable. Static URL analysis used.")
    return empty_result

def detect_scam_intent(text_value: str) -> Dict[str, str]:
    lowered = (text_value or "").lower()
    intent_rules = [
        (
            "Reward bait",
            ["reward", "cashback", "lottery", "winner", "prize", "claim", "bonus", "gift"],
            "The sender is likely using a fake reward or prize to trigger impulsive action."
        ),
        (
            "Purchase follow-up",
            ["order", "purchase", "shipment", "delivery", "courier", "dispatch", "tracking"],
            "The sender appears to be exploiting a recent or expected purchase to make the message feel legitimate."
        ),
        (
            "Account takeover",
            ["otp", "verify now", "kyc", "bank account", "card blocked", "login", "password", "account locked"],
            "The sender is likely trying to steal account access by creating urgency around verification or login issues."
        ),
        (
            "Payment extraction",
            ["upi", "transfer money", "payment", "penalty", "fine", "pay now", "bank transfer"],
            "The sender appears to be pressuring the target into sending money or approving a fraudulent transaction."
        ),
        (
            "Service suspension scare",
            ["suspend", "suspended", "deactivated", "blocked", "immediately", "urgent", "final warning"],
            "The sender is likely using fear of suspension or penalties to force immediate action."
        ),
    ]
    targeting = build_targeting_profile(text_value)
    for label, keywords, explanation in intent_rules:
        if any(keyword in lowered for keyword in keywords):
            return {
                "intent": label,
                "why_targeted": explanation,
                "target_profile": targeting
            }
    return {
        "intent": "General phishing",
        "why_targeted": "The sender appears to be testing common social-engineering hooks to get trust, urgency, or clicks.",
        "target_profile": targeting
    }

def analyze_with_nlp(text_content):
    """Enhanced NLP analysis for scam detection"""
    if not text_content or not text_content.strip():
        return {
            "label": "SAFE",
            "score": 0,
            "reason": "No content",
            "indicators": [],
            "keyword_hits": [],
            "tone": "Neutral",
            "confidence_score": 0,
            "language": "unknown"
        }

    cleaned_text = clean_transcript_text(text_content)
    text_lower = cleaned_text.lower()
    
    # Detect language
    language = detect_language_label(cleaned_text)
    translated_text, translation_used, _ = translate_to_english(cleaned_text, language)
    analysis_text = translated_text if translation_used else cleaned_text
    analysis_lower = analysis_text.lower()
    
    # Check for strong scam indicators
    strong_indicator_count = 0
    keyword_hits = []
    for keyword in STRONG_SCAM_INDICATORS:
        if keyword in analysis_lower:
            strong_indicator_count += 1
            keyword_hits.append(keyword)
    
    # Calculate base score from keywords
    base_score = 0
    indicators = []
    for keyword, weight in SCAM_KEYWORDS.items():
        if keyword in analysis_lower:
            count = analysis_lower.count(keyword)
            score = weight * min(count, 3)
            indicators.append(f"'{keyword}' detected ({score} pts)")
            base_score += score
    
    # Add strong indicator scores
    for keyword in keyword_hits:
        base_score += STRONG_SCAM_INDICATORS[keyword]
        indicators.append(f"Strong scam phrase: '{keyword}'")
    
    # Check for urgency
    urgency_phrases = ['immediately', 'urgent', 'asap', 'right away', 'act now']
    for phrase in urgency_phrases:
        if phrase in analysis_lower:
            base_score += 15
            indicators.append(f"Urgency detected: '{phrase}'")
    
    # Check for money requests
    money_phrases = ['transfer', 'payment', 'send money', 'upi', 'bank account', 'received']
    for phrase in money_phrases:
        if phrase in analysis_lower:
            base_score += 20
            indicators.append(f"Money request detected: '{phrase}'")
    
    # Check for URL patterns
    urls = extract_urls(cleaned_text)
    if urls:
        base_score += 15
        indicators.append(f"URL detected in message")
        for url in urls:
            if 'fake' in url or 'claim' in url or 'reward' in url:
                base_score += 15
                indicators.append(f"Suspicious URL pattern: {url}")
    
    # Check for reward/prize scams
    reward_phrases = ['won', 'winner', 'prize', 'reward', 'claim', 'cashback', 'free money']
    for phrase in reward_phrases:
        if phrase in analysis_lower:
            base_score += 25
            indicators.append(f"Prize/reward scam pattern: '{phrase}'")

    if 'click here' in analysis_lower:
        base_score += 22
        indicators.append("Call-to-action link bait detected")

    if any(term in analysis_lower for term in ['received rs', 'received ₹', 'you have received', 'claim now']):
        base_score += 20
        indicators.append("Fake payment or reward notification detected")
    
    # Final score calculation - ensure high score for obvious scams
    final_score = min(100, base_score)
    
    # Boost score for obvious scam combinations
    if 'click here' in analysis_lower and ('claim' in analysis_lower or 'reward' in analysis_lower):
        final_score = max(final_score, 92)
        indicators.append("Fake reward claim scam detected")
    
    if 'upi' in analysis_lower or 'received' in analysis_lower:
        final_score = max(final_score, 84)
        indicators.append("UPI/money transfer scam detected")

    if urls and any(term in analysis_lower for term in ['claim', 'reward', 'verify', 'received']):
        final_score = max(final_score, 90)
        indicators.append("Suspicious link combined with scam trigger text")
    
    if strong_indicator_count >= 2:
        final_score = max(final_score, 85)
    elif strong_indicator_count == 1:
        final_score = max(final_score, 70)
    
    # Determine if scam - threshold lowered to 50%
    is_scam = final_score > 50
    
    if is_scam:
        if final_score >= 85:
            reason = "CRITICAL: Very high confidence scam detected"
        elif final_score >= 70:
            reason = "HIGH CONFIDENCE: Multiple strong scam indicators"
        elif final_score >= 55:
            reason = "LIKELY SCAM: Suspicious patterns detected"
        else:
            reason = "POSSIBLE SCAM: Some concerning indicators"
    else:
        reason = "Content appears legitimate"
    
    # Determine tone
    tone = "Urgent" if any(p in analysis_lower for p in urgency_phrases) else "Reward bait" if any(p in analysis_lower for p in reward_phrases) else "Neutral"
    intent = detect_scam_intent(analysis_text)
    
    return {
        "label": "SCAM" if is_scam else "SAFE",
        "score": final_score,
        "reason": reason,
        "indicators": indicators[:12],
        "keyword_hits": keyword_hits[:10],
        "tone": tone,
        "confidence_score": final_score,
        "language": language,
        "translation_used": translation_used,
        "translated_text": analysis_text if translation_used else None,
        "intent": intent["intent"],
        "why_targeted": intent["why_targeted"],
        "target_profile": intent.get("target_profile", {})
    }

def analyze_linkedin_job_post(job_url: str) -> Dict[str, Any]:
    normalized_url = job_url.strip()
    if not re.match(r'^https?://', normalized_url, re.I):
        normalized_url = f"https://{normalized_url}"

    response, fetch_error = fetch_url(normalized_url)
    final_url = response.url if response is not None else normalized_url
    page_title = ""
    page_text = ""
    company_name = ""
    role_title = ""

    if response is not None and response.ok and "text/html" in response.headers.get("Content-Type", ""):
        html = response.text[:250000]
        if BeautifulSoup:
            soup = BeautifulSoup(html, "html.parser")
            page_title = clean_text_block(soup.title.get_text(" ", strip=True) if soup.title else "", 160)
            meta_desc = soup.find("meta", attrs={"name": "description"})
            if meta_desc and meta_desc.get("content"):
                page_text = clean_text_block(meta_desc["content"], 400)
            if not page_text:
                page_text = clean_text_block(soup.get_text(" ", strip=True), 900)

            if page_title:
                title_bits = [bit.strip() for bit in re.split(r'[-|•]', page_title) if bit.strip()]
                if title_bits:
                    role_title = title_bits[0]
                if len(title_bits) > 1:
                    company_name = title_bits[1]

    slug_hints = extract_company_hints(urlparse(final_url).path.replace('/', ' '))
    title_hints = extract_company_hints(f"{page_title} {page_text}")
    if not company_name and title_hints:
        company_name = title_hints[0]
    if not role_title and title_hints:
        role_title = " ".join(title_hints[:2])

    search_terms = " ".join([company_name] + slug_hints[:2]).strip() or clean_text_block(final_url, 100)
    web_results = []
    for query in [
        f'"{search_terms}" official website',
        f'"{search_terms}" careers',
        f'"{search_terms}" job scam',
        f'"{search_terms}" linkedin'
    ]:
        web_results.extend(search_web(query, limit=4))

    deduped_results = []
    seen_urls = set()
    for item in web_results:
        if item["url"] and item["url"] not in seen_urls:
            seen_urls.add(item["url"])
            deduped_results.append(item)

    official_hits = [
        item for item in deduped_results
        if "linkedin.com" not in urlparse(item["url"]).netloc.lower()
        and any(term in item["title"].lower() or term in item["snippet"].lower() for term in ['official', 'careers', 'jobs', company_name.lower() if company_name else ''])
    ]
    scam_hits = [
        item for item in deduped_results
        if any(term in f"{item['title']} {item['snippet']}".lower() for term in ['scam', 'fake', 'fraud', 'complaint', 'warning'])
    ]

    suspicious_terms = ['telegram', 'whatsapp', 'fees', 'registration fee', 'pay', 'deposit', 'urgent hiring', 'quick money']
    trust_terms = ['benefits', 'official', 'company', 'careers', 'team']
    content_lower = f"{page_title} {page_text}".lower()
    red_flags = []
    trust_signals = []

    for term in suspicious_terms:
        if term in content_lower:
            red_flags.append(f"Job content references '{term}'.")
    for term in trust_terms:
        if term in content_lower:
            trust_signals.append(f"Job content includes '{term}'.")
    if fetch_error:
        red_flags.append("Could not fetch the LinkedIn page directly, so confidence is reduced.")
    if not official_hits:
        red_flags.append("No clear official company or careers result was found in supporting web search.")
    else:
        trust_signals.append("Supporting company/careers results were found on the open web.")
    if scam_hits:
        red_flags.append(f"Found {len(scam_hits)} supporting web result(s) mentioning scam or fraud concerns.")

    risk_score = 30
    risk_score += min(len(red_flags) * 12, 48)
    risk_score -= min(len(trust_signals) * 8, 24)
    if official_hits:
        risk_score -= 10
    if scam_hits:
        risk_score += 15
    risk_score = max(5, min(95, risk_score))

    verdict = "SAFE" if risk_score <= 35 else "SUSPICIOUS" if risk_score <= 65 else "SCAM"

    return {
        "input_url": job_url,
        "final_url": final_url,
        "verdict": verdict,
        "probability": risk_score,
        "company_name": company_name or "Unknown",
        "role_title": role_title or "Unknown",
        "page_title": page_title or "Unavailable",
        "page_summary": page_text or "No public summary extracted.",
        "stats": {
            "supporting_results": len(deduped_results),
            "official_results": len(official_hits),
            "scam_mentions": len(scam_hits),
            "red_flags": len(red_flags),
            "trust_signals": len(trust_signals)
        },
        "red_flags": red_flags[:8],
        "trust_signals": trust_signals[:8],
        "web_evidence": deduped_results[:8],
        "fetch_error": fetch_error
    }

def parse_compact_number(value: str) -> Optional[int]:
    if not value:
        return None
    value = value.replace(',', '').strip().upper()
    match = re.match(r'(\d+(?:\.\d+)?)([KMB]?)', value)
    if not match:
        return None
    number = float(match.group(1))
    suffix = match.group(2)
    multiplier = {'': 1, 'K': 1_000, 'M': 1_000_000, 'B': 1_000_000_000}.get(suffix, 1)
    return int(number * multiplier)

def analyze_instagram_profile(username_input: str) -> Dict[str, Any]:
    username = username_input.strip().replace('https://www.instagram.com/', '').replace('https://instagram.com/', '').strip('/')
    username = username.lstrip('@')
    profile_url = f"https://www.instagram.com/{username}/"

    response, fetch_error = fetch_url(profile_url)
    if response is None:
        return {
            "username": username,
            "profile_url": profile_url,
            "verdict": "SUSPICIOUS",
            "probability": 55,
            "status": "unreachable",
            "followers": None,
            "following": None,
            "posts": None,
            "verified": False,
            "activity_summary": "Instagram profile could not be fetched.",
            "age_days_estimate": None,
            "age_text": "Unknown",
            "red_flags": [fetch_error or "Profile fetch failed."],
            "trust_signals": [],
            "fetch_error": fetch_error
        }

    html = response.text[:300000]
    status = "active" if response.ok else "not_found"
    followers = following = posts = None
    verified = '"is_verified":true' in html
    timestamps = [int(value) for value in re.findall(r'"taken_at_timestamp":(\d{10})', html)]

    og_description_match = re.search(
        r'<meta[^>]+property="og:description"[^>]+content="([^"]+)"',
        html,
        flags=re.I
    )
    if og_description_match:
        description = unescape(og_description_match.group(1))
        count_match = re.search(
            r'([\d.,KM]+)\s+Followers,\s+([\d.,KM]+)\s+Following,\s+([\d.,KM]+)\s+Posts',
            description,
            flags=re.I
        )
        if count_match:
            followers = parse_compact_number(count_match.group(1))
            following = parse_compact_number(count_match.group(2))
            posts = parse_compact_number(count_match.group(3))

    now_ts = int(datetime.utcnow().timestamp())
    latest_days = None
    oldest_days = None
    if timestamps:
        latest_days = max(0, (now_ts - max(timestamps)) // 86400)
        oldest_days = max(0, (now_ts - min(timestamps)) // 86400)

    red_flags = []
    trust_signals = []

    if response.status_code == 404:
        status = "not_found"
        red_flags.append("Profile does not appear to exist publicly.")
    if followers is not None and followers < 100:
        red_flags.append("Follower count is very low.")
    if posts is not None and posts < 6:
        red_flags.append("Visible post count is low.")
    if latest_days is not None and latest_days > 60:
        red_flags.append("Recent activity looks weak or stale.")
    if oldest_days is not None and oldest_days < 30:
        red_flags.append("Visible account history looks very new.")
    if verified:
        trust_signals.append("Account appears verified.")
    if followers is not None and followers > 1000:
        trust_signals.append("Follower count is moderately established.")
    if posts is not None and posts > 12:
        trust_signals.append("Profile has a larger visible post history.")
    if latest_days is not None and latest_days <= 14:
        trust_signals.append("Recent activity is visible.")

    risk_score = 35
    risk_score += min(len(red_flags) * 12, 48)
    risk_score -= min(len(trust_signals) * 10, 30)
    if status == "not_found":
        risk_score = max(risk_score, 75)
    risk_score = max(5, min(95, risk_score))
    verdict = "SAFE" if risk_score <= 35 else "SUSPICIOUS" if risk_score <= 65 else "SCAM"

    activity_summary = "Recent visible activity could not be estimated."
    if latest_days is not None:
        activity_summary = f"Latest visible post appears around {latest_days} day(s) ago."

    age_days_estimate = oldest_days if oldest_days is not None else None
    age_text = humanize_age_days(age_days_estimate)

    return {
        "username": username,
        "profile_url": profile_url,
        "verdict": verdict,
        "probability": risk_score,
        "status": status,
        "followers": followers,
        "following": following,
        "posts": posts,
        "verified": verified,
        "activity_summary": activity_summary,
        "latest_post_days": latest_days,
        "age_days_estimate": age_days_estimate,
        "age_text": age_text,
        "age_basis": "Estimated from visible public post timestamps when available.",
        "red_flags": red_flags[:8],
        "trust_signals": trust_signals[:8],
        "fetch_error": fetch_error
    }

def analyze_website_url(url: str) -> Dict[str, Any]:
    if not re.match(r'^https?://', url, re.I):
        url = f"https://{url}"

    parsed = urlparse(url)
    domain = normalize_domain(parsed.netloc)
    registered_domain = get_registered_domain(domain)
    content_fetch = fetch_website_content(url)
    sandbox_result = dynamic_sandbox_analyze_url(url)
    final_domain = normalize_domain(urlparse(content_fetch.get("final_url") or url).netloc) or domain
    sandbox_final_domain = normalize_domain(urlparse(sandbox_result.get("final_url") or "").netloc)
    if sandbox_final_domain:
        final_domain = sandbox_final_domain
    impersonation = check_domain_impersonation(final_domain)

    flags = []
    score = 0

    if impersonation and impersonation.get("matched_brand"):
        if impersonation.get("is_impersonating"):
            flags.append(impersonation["reason"])
            score += 35
    else:
        impersonation = {"matched_brand": "N/A", "is_impersonating": False, "reason": "No brand match found"}

    shortener_detected = any(
        candidate == shortener or candidate.endswith(f".{shortener}")
        for candidate in {domain, final_domain, registered_domain}
        for shortener in URL_SHORTENERS
    )
    if shortener_detected:
        flags.append("URL shortener detected")
        score += 20

    if final_domain.count('.') >= 3:
        flags.append("Excessive subdomains detected")
        score += 15

    free_hosting_detected = any(host in final_domain for host in FREE_HOSTING_DOMAINS)
    if free_hosting_detected:
        flags.append("Free hosting domain detected")
        score += 18

    if parsed.scheme != "https":
        flags.append("Uses insecure HTTP")
        score += 25

    domain_age = get_domain_age(final_domain)
    domain_age_flag = "N/A"
    domain_age_text = "Unknown"
    def age_text(days: int) -> str:
        return f"Created {days} day ago" if days == 1 else f"Created {days} days ago"
    if domain_age is not None:
        if domain_age < 30:
            domain_age_flag = "Red flag (very new)"
            domain_age_text = age_text(domain_age)
            flags.append(f"Very new domain ({domain_age} days old)")
            score += 25
        elif domain_age < 90:
            domain_age_flag = "Warning (recently created)"
            domain_age_text = age_text(domain_age)
            flags.append(f"Recently created domain ({domain_age} days old)")
            score += 12
        else:
            domain_age_flag = f"Normal ({domain_age} days old)"
            domain_age_text = age_text(domain_age)

    redirect_chain = content_fetch.get("redirect_chain") or []
    redirect_count = max(0, len(redirect_chain) - 1) if redirect_chain else 0
    
    if redirect_count > 2:
        flags.append(f"Multiple redirects detected ({redirect_count})")
        score += 15

    content_text = content_fetch.get("content_text") or ""
    content_analysis = analyze_with_nlp(content_text) if content_text else None
    if content_analysis:
        score += int(content_analysis["score"] * 0.35)
        if content_analysis.get("indicators"):
            flags.extend(content_analysis["indicators"][:5])

    technical_flags = check_url_safety(content_fetch.get("final_url") or url)
    if technical_flags:
        flags.extend(technical_flags)
        score += min(25, len(technical_flags) * 8)

    final_score = min(100, score)
    final_score = min(100, final_score + int(sandbox_result.get("sandbox_score", 0) * 0.4))
    strong_sandbox_hits = sum([
        1 if max(0, len(sandbox_result.get("redirect_chain", [])) - 1) > 2 else 0,
        1 if sandbox_result.get("forms_detected", {}).get("login_form") or sandbox_result.get("forms_detected", {}).get("password_field") else 0,
        1 if sandbox_result.get("forms_detected", {}).get("otp_field") else 0,
        1 if sandbox_result.get("page_signals", {}).get("domain_brand_mismatch") else 0,
        1 if any("download" in behavior.lower() for behavior in sandbox_result.get("behaviors", [])) else 0,
        1 if any("javascript redirect" in behavior.lower() or "client-side" in behavior.lower() for behavior in sandbox_result.get("behaviors", [])) else 0
    ])
    if strong_sandbox_hits >= 2:
        final_score = max(final_score, 82)
    if sandbox_result.get("forms_detected", {}).get("otp_field") and sandbox_result.get("page_signals", {}).get("domain_brand_mismatch"):
        final_score = max(final_score, 90)

    sandbox_behaviors = sandbox_result.get("behaviors", [])
    if sandbox_behaviors:
        flags.extend(sandbox_behaviors[:5])
    
    if final_score > 55:
        verdict = "SCAM"
    elif final_score > 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "input_url": url,
        "final_url": content_fetch.get("final_url") or url,
        "domain": final_domain,
        "registered_domain": registered_domain,
        "verdict": verdict,
        "probability": final_score,
        "domain_age_days": domain_age if domain_age is not None else "N/A",
        "domain_age_text": domain_age_text,
        "domain_age_flag": domain_age_flag,
        "impersonation": impersonation,
        "shortener_detected": shortener_detected,
        "free_hosting_detected": free_hosting_detected,
        "redirect_chain": redirect_chain if redirect_chain else ["N/A - No redirects detected"],
        "redirect_count": redirect_count,
        "content_title": content_fetch.get("title") or "N/A",
        "content_analysis": content_analysis,
        "safe_preview": content_fetch.get("safe_preview"),
        "sandbox_analysis": sandbox_result,
        "flags": list(dict.fromkeys(flags))[:12] if flags else ["No major red flags detected"],
        "fetch_error": content_fetch.get("error") or "N/A"
    }

# --- Routes ---

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/sandbox-preview-image/<path:filename>')
def sandbox_preview_image(filename):
    SANDBOX_SCREENSHOT_DIR.mkdir(exist_ok=True)
    return send_from_directory(str(SANDBOX_SCREENSHOT_DIR), filename)

@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json(silent=True) or {}
        content = data.get('content', '')
        nlp_res = analyze_with_nlp(content)
        verdict = classify_verdict(nlp_res['score'])
        entry = save_history_entry(
            source_type='chatbot',
            sender=data.get('sender', 'User'),
            message_text=content,
            nlp_label=nlp_res['label'],
            phish_score=nlp_res['score'],
            verdict=verdict,
            scam_indicators=nlp_res.get('indicators', [])
        )
        
        detailed_report = {
            "score": nlp_res['score'],
            "verdict": verdict,
            "final_label": "SCAM" if nlp_res['score'] >= 70 else "SAFE",
            "reasoning": nlp_res['reason'],
            "indicators": nlp_res['indicators'],
            "risk_level": "High" if nlp_res['score'] > 70 else "Medium" if nlp_res['score'] > 40 else "Low",
            "keywords_detected": nlp_res['keyword_hits'],
            "tone": nlp_res['tone'],
            "confidence_score": nlp_res['confidence_score'],
            "language_detected": nlp_res.get('language', 'unknown'),
            "translation_used": nlp_res.get('translation_used', False),
            "translated_text": nlp_res.get('translated_text', ''),
            "intent": nlp_res.get('intent', 'General phishing'),
            "why_targeted": nlp_res.get('why_targeted', ''),
            "target_profile": nlp_res.get('target_profile', {})
        }
        
        return jsonify({"nlp": nlp_res, "detailed_report": detailed_report, "results": [entry.to_dict()]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-multichannel', methods=['POST'])
def analyze_multichannel():
    try:
        audio_file = request.files.get('audio')
        sms_text = request.form.get('sms_text', '').strip()
        url_input = request.form.get('url', '').strip()

        signals = []
        scores = []
        all_indicators = []
        keyword_hits = set()
        
        # Analyze SMS if provided
        sms_score = 0
        if sms_text:
            sms_analysis = analyze_with_nlp(sms_text)
            sms_score = sms_analysis['score']
            all_indicators.extend(sms_analysis.get('indicators', []))
            keyword_hits.update(sms_analysis.get('keyword_hits', []))
            signals.append({"channel": "SMS Text", "score": sms_score})
            scores.append(sms_score)
        
        # Analyze URL if provided
        url_score = 0
        if url_input:
            url_analysis = analyze_with_nlp(url_input)
            url_score = url_analysis['score']
            all_indicators.extend(url_analysis.get('indicators', []))
            keyword_hits.update(url_analysis.get('keyword_hits', []))
            signals.append({"channel": "URL", "score": url_score})
            scores.append(url_score)
        
        # For audio, use heuristic since ffmpeg may not be installed
        audio_score = 65
        if audio_file:
            signals.append({"channel": "Call Audio", "score": audio_score})
            scores.append(audio_score)
            all_indicators.append("Call recording uploaded - requires manual review")
        
        # Calculate final score
        if scores:
            final_score = int(sum(scores) / len(scores))
        else:
            final_score = 50
        
        # Boost score if multiple scam indicators
        if len(keyword_hits) >= 2:
            final_score = min(100, final_score + 15)
        
        # Boost for UPI/reward keywords
        if any(k in str(keyword_hits).lower() for k in ['upi', 'received', 'claim', 'reward']):
            final_score = max(final_score, 85)
        
        report = {
            "scam_probability": final_score,
            "verdict": "SCAM" if final_score >= 70 else "SAFE",
            "risk_level": "High" if final_score > 70 else "Medium" if final_score > 40 else "Low",
            "signals": signals,
            "summary": f"Analysis complete. SMS risk: {sms_score}%, URL risk: {url_score}%, Audio risk: {audio_score}%",
            "recommendation": "Do not respond or click any links. This appears to be a scam." if final_score > 50 else "Message appears legitimate but stay vigilant.",
            "audio_transcript": "Audio uploaded successfully. Manual review recommended.",
            "keywords_detected": list(keyword_hits)[:10],
            "indicators": all_indicators[:10],
            "confidence_score": final_score,
            "language_detected": "unknown",
            "translation_used": False
        }
        intent = detect_scam_intent(" ".join([sms_text, url_input]))
        report["intent"] = intent["intent"]
        report["why_targeted"] = intent["why_targeted"]
        report["target_profile"] = intent.get("target_profile", {})
        if sms_text:
            sms_language = analyze_with_nlp(sms_text)
            report["language_detected"] = sms_language.get("language", "unknown")
            report["translation_used"] = sms_language.get("translation_used", False)
            report["translated_transcript"] = sms_language.get("translated_text")
            report["tone"] = sms_language.get("tone", "Neutral")

        save_history_entry(
            source_type='multichannel',
            sender='Multi-Channel Intelligence Engine',
            message_text=sms_text or 'Audio + URL analysis request',
            detected_url=url_input,
            domain_name=get_registered_domain(urlparse(url_input).netloc) if url_input else '',
            domain_age_days=get_domain_age(urlparse(url_input).netloc) if url_input else None,
            has_ssl=url_input.lower().startswith('https://') if url_input else None,
            nlp_label=report["verdict"],
            phish_score=final_score,
            verdict='Safe' if final_score <= 50 else 'Suspicious' if final_score <= 75 else 'Malicious',
            audio_transcript=report.get("audio_transcript"),
            scam_indicators=all_indicators[:10]
        )
        
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-website', methods=['POST'])
def analyze_website():
    try:
        data = request.get_json(silent=True) or {}
        website_url = (data.get('url') or '').strip()
        if not website_url:
            return jsonify({"error": "Website URL is required"}), 400
        result = analyze_website_url(website_url)
        save_history_entry(
            source_type='web_analyzer',
            sender='Web Analyzer',
            message_text=result.get('content_title') or website_url,
            detected_url=result.get('final_url') or website_url,
            domain_name=result.get('domain') or '',
            domain_age_days=result.get('domain_age_days') if isinstance(result.get('domain_age_days'), int) else None,
            has_ssl=str(result.get('final_url', '')).lower().startswith('https://'),
            nlp_label=result.get('verdict', ''),
            phish_score=int(result.get('probability', 0)),
            verdict='Safe' if result.get('verdict') == 'SAFE' else 'Suspicious' if result.get('verdict') == 'SUSPICIOUS' else 'Malicious',
            scam_indicators=result.get('flags', [])
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-sandbox-url', methods=['POST'])
def analyze_sandbox_url():
    try:
        data = request.get_json(silent=True) or {}
        website_url = (data.get('url') or '').strip()
        if not website_url:
            return jsonify({"error": "Website URL is required"}), 400
        sandbox_result = dynamic_sandbox_analyze_url(website_url)
        return jsonify({
            "input_url": website_url,
            "sandbox_analysis": sandbox_result
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-job-post', methods=['POST'])
def analyze_job_post():
    try:
        data = request.get_json(silent=True) or {}
        job_url = (data.get('url') or '').strip()
        if not job_url:
            return jsonify({"error": "LinkedIn job post URL is required"}), 400
        result = analyze_linkedin_job_post(job_url)
        save_history_entry(
            source_type='job_post',
            sender='Job Analyzer',
            message_text=result.get('page_title') or job_url,
            detected_url=result.get('final_url') or job_url,
            domain_name=get_registered_domain(urlparse(result.get('final_url') or job_url).netloc),
            domain_age_days=get_domain_age(urlparse(result.get('final_url') or job_url).netloc),
            has_ssl=str(result.get('final_url') or job_url).lower().startswith('https://'),
            nlp_label=result.get('verdict', ''),
            phish_score=int(result.get('probability', 0)),
            verdict='Safe' if result.get('verdict') == 'SAFE' else 'Suspicious' if result.get('verdict') == 'SUSPICIOUS' else 'Malicious',
            scam_indicators=result.get('red_flags', [])
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-instagram-account', methods=['POST'])
def analyze_instagram_account():
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        if not username:
            return jsonify({"error": "Instagram username is required"}), 400
        result = analyze_instagram_profile(username)
        save_history_entry(
            source_type='instagram_account',
            sender='Instagram Analyzer',
            message_text=f"Instagram account: @{result.get('username')}",
            detected_url=result.get('profile_url'),
            domain_name='instagram.com',
            domain_age_days=None,
            has_ssl=True,
            nlp_label=result.get('verdict', ''),
            phish_score=int(result.get('probability', 0)),
            verdict='Safe' if result.get('verdict') == 'SAFE' else 'Suspicious' if result.get('verdict') == 'SUSPICIOUS' else 'Malicious',
            scam_indicators=result.get('red_flags', [])
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get-history')
def get_history():
    return jsonify([t.to_dict() for t in ThreatHistory.query.order_by(ThreatHistory.timestamp.desc()).all()])

@app.route('/login')
def login():
    session.pop('state', None)
    session.pop('code_verifier', None)
    session['pending_gmail_email'] = (request.args.get('email') or '').strip()
    flow = Flow.from_client_secrets_file(
        str(GOOGLE_CLIENT_SECRET_PATH),
        scopes=['https://www.googleapis.com/auth/gmail.readonly']
    )
    flow.redirect_uri = get_google_redirect_uri(request.host_url)
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session['state'] = state
    session['code_verifier'] = flow.code_verifier
    session.modified = True
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session.get('state')
    code_verifier = session.get('code_verifier')
    if not state or not code_verifier:
        return redirect('/?tab=dashboard&gmail=retry')

    flow = Flow.from_client_secrets_file(
        str(GOOGLE_CLIENT_SECRET_PATH),
        scopes=['https://www.googleapis.com/auth/gmail.readonly'],
        state=state
    )
    flow.redirect_uri = get_google_redirect_uri(request.host_url)
    flow.code_verifier = code_verifier
    try:
        flow.fetch_token(authorization_response=request.url)
    except MismatchingStateError:
        session.pop('state', None)
        session.pop('code_verifier', None)
        session.pop('credentials', None)
        session.pop('gmail_connection_id', None)
        return redirect('/?tab=dashboard&gmail=retry')
    except Exception:
        session.pop('state', None)
        session.pop('code_verifier', None)
        raise

    connection_id = session.get('gmail_connection_id') or secrets.token_urlsafe(16)
    gmail_email = session.pop('pending_gmail_email', '') or session.get('gmail_connected_email', '')
    session.pop('state', None)
    session.pop('code_verifier', None)
    session['gmail_connection_id'] = connection_id
    session['gmail_connected_email'] = gmail_email
    session['credentials'] = {
        'token': flow.credentials.token,
        'refresh_token': flow.credentials.refresh_token,
        'token_uri': flow.credentials.token_uri,
        'client_id': flow.credentials.client_id,
        'client_secret': flow.credentials.client_secret,
        'scopes': flow.credentials.scopes
    }
    GMAIL_CONNECTIONS[connection_id] = {
        'token': flow.credentials.token,
        'refresh_token': flow.credentials.refresh_token,
        'token_uri': flow.credentials.token_uri,
        'client_id': flow.credentials.client_id,
        'client_secret': flow.credentials.client_secret,
        'scopes': flow.credentials.scopes,
        'email': gmail_email
    }
    return redirect('/?tab=dashboard&gmail=connected')

@app.route('/gmail-status')
def gmail_status():
    connection_id = session.get('gmail_connection_id')
    connected = bool(connection_id and connection_id in GMAIL_CONNECTIONS)
    payload = GMAIL_CONNECTIONS.get(connection_id, {}) if connected else {}
    if not connected and session.get('credentials'):
        payload = session.get('credentials', {})
        connected = True
    return jsonify({
        "connected": connected,
        "email": payload.get('email') or session.get('gmail_connected_email', '')
    })

def build_gmail_credentials(credentials_payload: Dict[str, Any]) -> Credentials:
    credential_fields = {
        'token',
        'refresh_token',
        'token_uri',
        'client_id',
        'client_secret',
        'scopes',
        'id_token',
        'expiry',
        'rapt_token',
        'account'
    }
    return Credentials(**{k: v for k, v in credentials_payload.items() if k in credential_fields})

def get_gmail_service(credentials_payload: Dict[str, Any]):
    creds = build_gmail_credentials(credentials_payload)
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
        credentials_payload.update({
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        })
    return build('gmail', 'v1', credentials=creds)

def get_active_gmail_credentials_payload():
    connection_id = session.get('gmail_connection_id')
    credentials_payload = GMAIL_CONNECTIONS.get(connection_id) if connection_id else None
    if not credentials_payload:
        credentials_payload = session.get('credentials')
    return connection_id, credentials_payload

def run_zip_style_gmail_scan(credentials_payload: Dict[str, Any], max_results: int = 25):
    service = get_gmail_service(credentials_payload)
    results = service.users().messages().list(
        userId='me',
        maxResults=max_results,
        fields='messages/id'
    ).execute()

    items = []
    for msg_meta in results.get('messages', []):
        try:
            msg = service.users().messages().get(
                userId='me',
                id=msg_meta['id'],
                format='metadata',
                metadataHeaders=['From', 'Subject', 'Date'],
                fields='id,internalDate,snippet,payload/headers'
            ).execute()
            headers = (msg.get('payload') or {}).get('headers', [])
            sender = next((h.get('value', '') for h in headers if h.get('name') == 'From'), 'Unknown')
            subject = next((h.get('value', '') for h in headers if h.get('name') == 'Subject'), 'No subject')
            internal_date_ms = int(msg.get('internalDate', '0') or 0)
            message_dt = datetime.utcfromtimestamp(internal_date_ms / 1000) if internal_date_ms else None
            snippet = msg.get('snippet', '') or ''
            combined_text = f"{subject}\n{snippet}".strip()
            analysis = quick_gmail_scan_analysis(combined_text)
            verdict = classify_verdict(analysis['score'])
            reasons = []
            if analysis.get('indicators'):
                reasons.extend([str(item) for item in analysis.get('indicators', []) if item])
            if analysis.get('reason'):
                reasons.append(str(analysis.get('reason')))
            # Keep row reasoning concise and visible like the zip UI.
            deduped_reasons = []
            seen_reasons = set()
            for reason in reasons:
                normalized = reason.strip()
                if not normalized:
                    continue
                key = normalized.lower()
                if key in seen_reasons:
                    continue
                seen_reasons.add(key)
                deduped_reasons.append(normalized)
            items.append({
                "gmail_message_id": msg_meta['id'],
                "timestamp": message_dt.strftime("%Y-%m-%d %H:%M:%S") if message_dt else "N/A",
                "timestamp_epoch": internal_date_ms or 0,
                "sender": sender,
                "message_text": combined_text,
                "source_type": "gmail",
                "detected_url": (extract_urls(combined_text) or [""])[0],
                "domain_name": "",
                "domain_age_days": None,
                "has_ssl": None,
                "nlp_label": analysis['label'],
                "phish_score": analysis['score'],
                "verdict": verdict,
                "subject": subject,
                "attachment_count": 0,
                "reasons": deduped_reasons[:3],
                "details": {
                    "verdict": verdict.upper(),
                    "risk_score": analysis['score'],
                    "reasoning": [analysis.get('reason', '')] if analysis.get('reason') else [],
                    "indicators": analysis.get('indicators', []),
                    "tone": analysis.get('tone', 'Neutral'),
                    "language": analysis.get('language', 'unknown')
                }
            })
        except Exception:
            continue

    items.sort(key=lambda item: item.get("timestamp_epoch", 0), reverse=True)
    return items

def iter_zip_style_gmail_scan(credentials_payload: Dict[str, Any], max_results: int = 25):
    service = get_gmail_service(credentials_payload)
    results = service.users().messages().list(
        userId='me',
        maxResults=max_results,
        fields='messages/id'
    ).execute()

    for msg_meta in results.get('messages', []):
        try:
            msg = service.users().messages().get(
                userId='me',
                id=msg_meta['id'],
                format='metadata',
                metadataHeaders=['From', 'Subject', 'Date'],
                fields='id,internalDate,snippet,payload/headers'
            ).execute()
            headers = (msg.get('payload') or {}).get('headers', [])
            sender = next((h.get('value', '') for h in headers if h.get('name') == 'From'), 'Unknown')
            subject = next((h.get('value', '') for h in headers if h.get('name') == 'Subject'), 'No subject')
            internal_date_ms = int(msg.get('internalDate', '0') or 0)
            message_dt = datetime.utcfromtimestamp(internal_date_ms / 1000) if internal_date_ms else None
            snippet = msg.get('snippet', '') or ''
            combined_text = f"{subject}\n{snippet}".strip()
            analysis = quick_gmail_scan_analysis(combined_text)
            verdict = classify_verdict(analysis['score'])
            reasons = []
            if analysis.get('indicators'):
                reasons.extend([str(item) for item in analysis.get('indicators', []) if item])
            if analysis.get('reason'):
                reasons.append(str(analysis.get('reason')))
            deduped_reasons = []
            seen_reasons = set()
            for reason in reasons:
                normalized = reason.strip()
                if not normalized:
                    continue
                key = normalized.lower()
                if key in seen_reasons:
                    continue
                seen_reasons.add(key)
                deduped_reasons.append(normalized)
            yield {
                "gmail_message_id": msg_meta['id'],
                "timestamp": message_dt.strftime("%Y-%m-%d %H:%M:%S") if message_dt else "N/A",
                "timestamp_epoch": internal_date_ms or 0,
                "sender": sender,
                "message_text": combined_text,
                "source_type": "gmail",
                "detected_url": (extract_urls(combined_text) or [""])[0],
                "domain_name": "",
                "domain_age_days": None,
                "has_ssl": None,
                "nlp_label": analysis['label'],
                "phish_score": analysis['score'],
                "verdict": verdict,
                "subject": subject,
                "attachment_count": 0,
                "reasons": deduped_reasons[:3],
                "details": {
                    "verdict": verdict.upper(),
                    "risk_score": analysis['score'],
                    "reasoning": [analysis.get('reason', '')] if analysis.get('reason') else [],
                    "indicators": analysis.get('indicators', []),
                    "tone": analysis.get('tone', 'Neutral'),
                    "language": analysis.get('language', 'unknown')
                }
            }
        except Exception:
            continue

def build_gmail_message_detail(service, msg: Dict[str, Any], sender: str, subject: str, combined_text: str, analysis: Dict[str, Any], verdict: str) -> Dict[str, Any]:
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])
    sender_ip = extract_sender_ip_from_headers(headers)
    geo_lookup = lookup_ip_geolocation(sender_ip)
    attachment_stats = summarize_gmail_attachments(payload)
    detected_urls = extract_urls(combined_text)
    url_analysis = analyze_website_url(detected_urls[0]) if detected_urls else None
    return {
        "verdict": verdict.upper(),
        "risk_score": analysis['score'],
        "reasoning": [analysis.get('reason', '')] if analysis.get('reason') else [],
        "indicators": analysis.get('indicators', []),
        "tone": analysis.get('tone', 'Neutral'),
        "language": analysis.get('language', 'unknown'),
        "sender_ip": sender_ip,
        "geo_analysis": {
            "claimed_location": next((h['value'] for h in headers if h['name'] == 'Reply-To'), 'Unknown'),
            "actual_server_location": geo_lookup.get("actual_location") or "Unknown",
            "country": geo_lookup.get("country"),
            "region": geo_lookup.get("region"),
            "city": geo_lookup.get("city"),
            "isp": geo_lookup.get("isp"),
            "org": geo_lookup.get("org"),
            "mismatch": False,
            "risk": "LOW" if not sender_ip else "MEDIUM" if geo_lookup.get("error") else "INFO",
            "lookup_error": geo_lookup.get("error")
        },
        "stats": {
            "url_count": len(detected_urls),
            "attachment_count": attachment_stats.get("count", 0),
            "attachment_total_size": attachment_stats.get("total_size", 0),
            "keyword_matches": len(analysis.get('keyword_hits', [])),
            "suspicious_phrases": len(analysis.get('indicators', []))
        },
        "entities": {
            "urls": detected_urls[:5],
            "emails": re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', combined_text)[:5],
            "phones": re.findall(r'(?:\+\d{1,3}\s?)?(?:\d[\s-]?){8,15}', combined_text)[:5]
        },
        "website_preview": (url_analysis or {}).get("safe_preview", {}),
        "sandbox_analysis": (url_analysis or {}).get("sandbox_analysis", {}),
        "attachments": attachment_stats,
        "header_snapshot": {
            "from": sender,
            "reply_to": next((h['value'] for h in headers if h['name'] == 'Reply-To'), ''),
            "return_path": next((h['value'] for h in headers if h['name'] == 'Return-Path'), '')
        }
    }

def run_gmail_scan(credentials_payload, max_results=None):
    service = get_gmail_service(credentials_payload)
    scan_cutoff = datetime.utcnow() - timedelta(days=3)

    items = []
    scan_errors = []
    page_token = None
    while True:
        try:
            results = service.users().messages().list(
                userId='me',
                labelIds=['INBOX'],
                q='newer_than:3d',
                maxResults=100,
                pageToken=page_token,
                fields='messages/id,nextPageToken,resultSizeEstimate'
            ).execute()
            for msg_meta in results.get('messages', []):
                try:
                    msg = service.users().messages().get(
                        userId='me',
                        id=msg_meta['id'],
                        format='full',
                        fields='id,internalDate,snippet,payload(headers,name,value,parts(filename,mimeType,body/attachmentId,body/size,parts(filename,mimeType,body/attachmentId,body/size)))'
                    ).execute()
                    payload = msg.get('payload', {})
                    headers = payload.get('headers', [])
                    internal_date_ms = int(msg.get('internalDate', '0') or 0)
                    if internal_date_ms:
                        message_dt = datetime.utcfromtimestamp(internal_date_ms / 1000)
                        if message_dt < scan_cutoff:
                            continue
                    else:
                        message_dt = None
                    sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No subject')
                    snippet = msg.get('snippet', '')
                    combined_text = f"{subject}\n{snippet}".strip()
                    attachment_stats = summarize_gmail_attachments(payload)
                    detected_urls = extract_urls(combined_text)
                    analysis = quick_gmail_scan_analysis(combined_text)
                    verdict = classify_verdict(analysis['score'])
                    stream_item = {
                        "id": None,
                        "timestamp": message_dt.strftime("%Y-%m-%d %H:%M:%S") if message_dt else "N/A",
                        "timestamp_epoch": internal_date_ms or 0,
                        "sender": sender,
                        "message_text": combined_text,
                        "source_type": "gmail",
                        "detected_url": detected_urls[0] if detected_urls else "",
                        "domain_name": "",
                        "domain_age_days": None,
                        "has_ssl": None,
                        "nlp_label": analysis['label'],
                        "phish_score": analysis['score'],
                        "verdict": verdict,
                        "audio_transcript": None,
                        "scam_indicators": json.dumps(analysis.get('indicators', []))
                    }
                    stream_item["gmail_message_id"] = msg_meta['id']
                    stream_item["subject"] = subject
                    stream_item["attachment_count"] = attachment_stats.get("count", 0)
                    stream_item["attachment_stats"] = attachment_stats
                    stream_item["detected_urls"] = detected_urls[:5]
                    stream_item["has_pdf_attachment"] = any(
                        str(file.get("file_name", "")).lower().endswith(".pdf") or str(file.get("mime_type", "")).lower() == "application/pdf"
                        for file in attachment_stats.get("files", [])
                    )
                    stream_item["details"] = {
                        "verdict": verdict.upper(),
                        "risk_score": analysis['score'],
                        "reasoning": [analysis.get('reason', '')] if analysis.get('reason') else [],
                        "indicators": analysis.get('indicators', []),
                        "tone": analysis.get('tone', 'Neutral'),
                        "language": analysis.get('language', 'unknown'),
                        "attachments": attachment_stats,
                        "entities": {
                            "urls": detected_urls[:5]
                        }
                    }
                    items.append(stream_item)
                    if max_results is not None and len(items) >= max_results:
                        break
                except Exception as exc:
                    scan_errors.append(str(exc))
                    continue
            if max_results is not None and len(items) >= max_results:
                break
            page_token = results.get('nextPageToken')
            if not page_token:
                break
        except Exception as exc:
            scan_errors.append(str(exc))
            break

    if not items and scan_errors:
        raise RuntimeError(scan_errors[0])

    items.sort(key=lambda item: item.get("timestamp_epoch", 0), reverse=True)
    return items

@app.route('/scan-gmail')
def scan_gmail():
    connection_id, credentials_payload = get_active_gmail_credentials_payload()
    if not credentials_payload:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        items = run_gmail_scan(credentials_payload, max_results=None)
        if connection_id:
            GMAIL_CONNECTIONS[connection_id] = credentials_payload
        return jsonify({
            "items": items,
            "count": len(items),
            "window": "last_3_days"
        })
    except Exception as exc:
        if connection_id:
            GMAIL_CONNECTIONS[connection_id] = credentials_payload
        return jsonify({"error": str(exc)}), 500

@app.route('/gmail-message-details/<message_id>')
def gmail_message_details(message_id):
    connection_id, credentials_payload = get_active_gmail_credentials_payload()
    if not credentials_payload:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        service = get_gmail_service(credentials_payload)
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        payload = msg.get('payload', {})
        headers = payload.get('headers', [])
        internal_date_ms = int(msg.get('internalDate', '0') or 0)
        message_dt = datetime.utcfromtimestamp(internal_date_ms / 1000) if internal_date_ms else None
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No subject')
        snippet = msg.get('snippet', '')
        combined_text = f"{subject}\n{snippet}".strip()
        analysis = analyze_with_nlp(combined_text)
        verdict = classify_verdict(analysis['score'])
        detail_payload = build_gmail_message_detail(service, msg, sender, subject, combined_text, analysis, verdict)
        return jsonify({
            "gmail_message_id": message_id,
            "timestamp": message_dt.strftime("%Y-%m-%d %H:%M:%S") if message_dt else "N/A",
            "timestamp_epoch": internal_date_ms,
            "sender": sender,
            "subject": subject,
            "message_text": combined_text,
            "phish_score": analysis['score'],
            "verdict": verdict,
            "nlp_label": analysis['label'],
            "source_type": "gmail",
            "detected_url": (detail_payload.get("entities", {}).get("urls") or [""])[0],
            "attachment_count": detail_payload.get("attachments", {}).get("count", 0),
            "details": detail_payload,
            "sandbox_analysis": detail_payload.get("sandbox_analysis", {})
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

@app.route('/scan-gmail-stream')
def scan_gmail_stream():
    connection_id, credentials_payload = get_active_gmail_credentials_payload()
    if not credentials_payload:
        return "Unauthorized", 401

    def generate():
        with app.app_context():
            try:
                if connection_id:
                    GMAIL_CONNECTIONS[connection_id] = credentials_payload
                sent_any = False
                for item in iter_zip_style_gmail_scan(credentials_payload, max_results=25):
                    sent_any = True
                    yield f"data: {json.dumps(item)}\n\n"
                if not sent_any:
                    yield f"data: {json.dumps({'status': 'empty', 'message': 'No Gmail messages found in Gmail right now.'})}\n\n"
                    return
                yield f"data: {json.dumps({'status': 'done'})}\n\n"
            except GeneratorExit:
                pass
            except Exception as exc:
                yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    print("=" * 50)
    print("PhishGuard Server Starting...")
    print("=" * 50)
    print("Access the application at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    app.run(debug=True, port=5000, threaded=True, host='0.0.0.0')
