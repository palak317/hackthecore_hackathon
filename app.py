import os
import re
import socket
import ssl
import whois
import json
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, Response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

# Google Auth Libraries
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Hugging Face Integration
from transformers import pipeline

app = Flask(__name__)
# Fixed secret key is essential to keep session data safe between redirects
app.secret_key = "phishguard_secure_dev_key_123"
CORS(app)

# --- NLP Model Initialization ---
print("Loading Reliable Phishing Detection Model...")
try:
    # This model is specifically fine-tuned for SMS/Spam detection
    classifier = pipeline(
        "text-classification",
        model="mrm8488/bert-tiny-finetuned-sms-spam-detection"
    )
    print("Phishing AI loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    classifier = pipeline("text-classification")

# --- REPUTATION LAYER (Strict Whitelisting) ---
# Adding common domains found in your screenshots to prevent false positives
TRUSTED_DOMAINS = [
    'google.com', 'microsoft.com', 'mongodb.com', 'upwork.com',
    'github.com', 'linkedin.com', 'firebase.com', 'stanford.edu',
    'apple.com', 'amazon.com', 'netflix.com', 'facebook.com',
    'coursera.org', 'alibaba.com', 'dribbble.com', 'quora.com',
    'et-ai.com', 'freelancer.com', 'zoom.us', 'slack.com', 'trello.com'
]

# --- SQLAlchemy Configuration ---
MYSQL_PASSWORD = ''
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root:{MYSQL_PASSWORD}@localhost/phishguard'
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
            "verdict": self.verdict
        }


with app.app_context():
    db.create_all()


# --- Analysis Logic ---

def extract_urls(text):
    # Improved regex to handle various link formats
    return re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)


def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        return (datetime.now() - creation_date).days if creation_date else None
    except:
        return None


def analyze_with_nlp(text_content):
    if not text_content or not text_content.strip():
        return {"label": "SAFE", "score": 0, "reason": "No content"}

    result = classifier(text_content[:512])
    label = result[0]['label']
    conf_score = result[0]['score']

    is_phish = (label == "LABEL_1")
    risk_score = int(conf_score * 100) if is_phish else int((1 - conf_score) * 100)

    return {
        "label": "PHISHING" if is_phish else "SAFE",
        "score": risk_score,
        "reason": "Suspicious intent patterns" if is_phish else "Intent appears standard"
    }


def process_analysis(sender, content, source):
    """Refined analysis logic focusing on HTTP/HTTPS and Whitelisting."""
    nlp_res = analyze_with_nlp(content)
    urls = extract_urls(content)
    final_results = []

    if not urls:
        # PURE NLP VERDICT: If no URL, we trust NLP more but keep a safe threshold
        verdict = "Safe" if nlp_res['score'] < 65 else "Suspicious"
        entry = ThreatHistory(
            source_type=source, sender=sender, message_text=content,
            nlp_label=nlp_res['label'], phish_score=nlp_res['score'], verdict=verdict
        )
        db.session.add(entry)
        final_results.append(entry)
    else:
        for url in urls:
            domain = url.split("//")[-1].split("/")[0].lower()
            is_https = url.lower().startswith("https://")

            # 1. Reputation Check (Whitelist)
            is_trusted = any(td in domain for td in TRUSTED_DOMAINS)

            if is_trusted:
                if is_https:
                    score = 2  # Extremely safe
                    verdict = "Safe"
                else:
                    # If a trusted brand uses http (unlikely but possible), mark as suspicious
                    score = 45
                    verdict = "Suspicious"
            else:
                # 2. Unknown Domain Logic
                base_score = nlp_res['score']

                # Rule: http is not safe
                if not is_https:
                    score = max(80, base_score + 20)
                    verdict = "Malicious"
                else:
                    # https is a good indicator but not a guarantee for unknown domains
                    # We blend the AI result with a slight safety bonus for SSL
                    score = int(base_score * 0.8)
                    verdict = "Suspicious" if score > 50 else "Safe"

            new_threat = ThreatHistory(
                source_type=source, sender=sender, message_text=content,
                detected_url=url, domain_name=domain, domain_age_days=None,
                has_ssl=is_https, nlp_label=nlp_res['label'],
                phish_score=min(100, score), verdict=verdict
            )
            db.session.add(new_threat)
            final_results.append(new_threat)

    db.session.commit()
    return nlp_res, [r.to_dict() for r in final_results]


# --- Routes ---

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file("client_secret.json",
                                         scopes=['https://www.googleapis.com/auth/gmail.readonly'])
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session['state'], session['code_verifier'] = state, flow.code_verifier
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    flow = Flow.from_client_secrets_file("client_secret.json",
                                         scopes=['https://www.googleapis.com/auth/gmail.readonly'],
                                         state=session['state'])
    flow.redirect_uri = url_for('callback', _external=True)
    flow.code_verifier = session['code_verifier']
    flow.fetch_token(authorization_response=request.url)
    session['credentials'] = {'token': flow.credentials.token, 'refresh_token': flow.credentials.refresh_token,
                              'token_uri': flow.credentials.token_uri, 'client_id': flow.credentials.client_id,
                              'client_secret': flow.credentials.client_secret, 'scopes': flow.credentials.scopes}
    return redirect('/')


@app.route('/scan-gmail-stream')
def scan_gmail_stream():
    if 'credentials' not in session: return "Unauthorized", 401
    creds = Credentials(**session['credentials'])

    def generate():
        try:
            service = build('gmail', 'v1', credentials=creds)
            # Scanning 25 latest messages
            results = service.users().messages().list(userId='me', maxResults=25).execute()

            for msg_meta in results.get('messages', []):
                try:
                    msg = service.users().messages().get(userId='me', id=msg_meta['id']).execute()
                    payload = msg.get('payload', {})
                    headers = payload.get('headers', [])
                    sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                    snippet = msg.get('snippet', '')

                    with app.app_context():
                        _, results_list = process_analysis(sender, snippet, 'gmail')
                        for r in results_list:
                            yield f"data: {json.dumps(r)}\n\n"
                except:
                    continue
        except GeneratorExit:
            pass

    return Response(generate(), mimetype='text/event-stream')


@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    try:
        data = request.json
        nlp_res, results = process_analysis(data.get('sender', 'User'), data.get('content', ''), 'sms_bot')
        return jsonify({"nlp": nlp_res, "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get-history')
def get_history():
    return jsonify([t.to_dict() for t in ThreatHistory.query.order_by(ThreatHistory.timestamp.desc()).all()])


@app.route('/')
def index(): return send_from_directory('.', 'index.html')


if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)