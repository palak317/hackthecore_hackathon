# 🛡️ CortexGuard – AI-Powered Multi-Channel Phishing Detection System

🚀 **Real-time phishing detection across emails, SMS, calls, URLs, and attachments using AI + sandbox simulation**

---

## 📌 Overview

CortexGuard is an intelligent cybersecurity platform designed to detect and explain phishing attacks in real-time. Unlike traditional systems that rely on static rules, CortexGuard uses **AI-driven analysis, sandbox simulation, and multi-channel intelligence** to identify threats before users fall victim.

---

## 🎯 Key Features

### 🔍 Multi-Channel Detection

* Gmail email scanning (last 72 hours + live stream)
* SMS and chatbot text analysis
* Voice call (vishing) detection via speech-to-text
* URL and website analysis
* Job & social media scam detection

---

### 🧠 AI Threat Intelligence

* NLP-based phishing detection
* Keyword + behavioral analysis
* Brand & role impersonation detection (e.g., fake bank manager)
* Multilingual support (Hindi, Marathi, etc.)

---

### 🌐 Sandbox Simulation Engine (🔥 Unique Feature)

* Safe URL preview without opening in browser
* Detects:

  * Fake login pages
  * Redirect chains
  * Suspicious content behavior
* Prevents user exposure to malicious sites

---

### 📁 Attachment Analysis

* PDF text extraction
* Image + steganography detection
* Executable file risk detection
* Hidden phishing content detection

---

### 📊 Explainable AI

* Risk score (0–100)
* Clear reasoning (why flagged)
* 2-line summary for users

---

### 📲 Real-Time Alerts

* WhatsApp alerts using Twilio API
* Instant warning for high-risk threats

---

### 🗄️ Threat History

* Stores all analyzed threats
* Enables re-analysis and tracking
* Built using SQLite database

---

## 🏗️ System Architecture

CortexGuard follows a **pipeline-based architecture**:

```
User → Frontend → Flask API → Analysis Pipelines → AI Intelligence → Sandbox → Risk Engine → Database → Dashboard → Alerts
```

### 🔧 Core Modules:

* Gmail Analyzer
* Chatbot Analyzer
* Web Analyzer
* MCIE (Multi-Channel Intelligence Engine)
* Sandbox Engine
* Risk Scoring Engine

---

## ⚙️ Tech Stack

### 🖥️ Frontend

* HTML, CSS, JavaScript
* Real-time dashboard UI

### 🧠 Backend

* Python (Flask)
* REST APIs

### 🤖 AI / ML

* NLP models (Transformers / TF-IDF)
* Heuristic scoring
* OCR & speech-to-text

### 🔗 Integrations

* Google Gmail API (OAuth)
* Twilio WhatsApp API
* WHOIS / Geo lookup APIs

### 🗄️ Database

* SQLite (`phishguard.db`)

---

## 🚀 How It Works

1. User connects Gmail or inputs data
2. System extracts text, URLs, attachments
3. AI models analyze content
4. Suspicious links/files sent to sandbox
5. Risk score is calculated
6. Results shown in dashboard
7. Alerts sent if high risk detected

---

## 📸 Features in Action

* 📊 Real-time threat dashboard
* 🔍 “View Details” deep analysis
* 🌐 Safe website preview (sandbox)
* 📲 WhatsApp phishing alerts

---

## 🔐 Security Measures

* No execution of suspicious files
* URLs analyzed in sandbox (safe environment)
* Credentials stored securely using environment variables

---

## 🏆 What Makes This Unique

✔ Multi-channel phishing detection
✔ Sandbox-based safe simulation
✔ Explainable AI (not black-box)
✔ Real-time alerts
✔ Regional language support
✔ Detects human-level scams (impersonation)

---

## 📦 Setup Instructions

### 1. Clone Repository

```
git clone https://github.com/your-username/phishguard.git
cd phishguard
```

---

### 2. Create Virtual Environment

```
python -m venv myenv
source myenv/bin/activate  # Windows: myenv\Scripts\activate
```

---

### 3. Install Dependencies

```
pip install -r requirements.txt
```

---


---

### 5. Run Application

```
python app.py
```

---

## 📌 Future Enhancements

* Chrome extension for real-time protection
* Advanced ML model training
* Mobile app integration
* Threat intelligence sharing system

---

## 👨‍💻 Team

**Team Name:** BitsCompile,
**Hackathon:** Hackup 2026

---

## 📄 License

This project is for educational and hackathon purposes.

---

## ⭐ Support

If you like this project, please ⭐ the repository!
