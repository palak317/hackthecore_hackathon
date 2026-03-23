# 🧠 CortexGuard AI

### Adaptive Threat Intelligence Platform

> Real-time AI-powered phishing and scam detection system for emails, messages, and links.

---

## 🚀 Overview

CortexGuard AI is a **multi-layered security platform** designed to detect phishing, scams, and malicious content using a combination of:

* 🧠 NLP-based semantic analysis
* 🔗 URL & domain intelligence
* 🛡️ Protocol and security validation
* ⚡ Real-time streaming detection

Unlike traditional systems, CortexGuard focuses on **context-aware threat detection** with explainable insights.

---

## ✨ Features

* 🔍 **Real-time Gmail scanning** (last 72 hours)
* 🤖 **AI Chatbot for message analysis**
* 🌐 **URL extraction & domain verification**
* 🧠 **NLP-based scam detection (Hugging Face)**
* ⚡ **Live scanning stream (SSE)**
* 📊 **Threat dashboard with analytics**
* 🗂️ **Archive with filtering (Safe / Suspicious)**
* 🔐 **OAuth-based Gmail integration**
* 💡 **Explainable AI output (reason + score)**

---

## 🧠 How It Works

### 🔄 Multi-Layer Detection Pipeline

1. **Data Ingestion**

   * Gmail API fetches recent emails
   * User input via chatbot

2. **AI Semantic Analysis**

   * Detects intent (urgency, fraud patterns, tone)

3. **URL Extraction**

   * Identifies links using regex

4. **Reputation Check**

   * Matches domain with trusted whitelist

5. **Technical Validation**

   * Domain age (WHOIS)
   * SSL certificate check

6. **Protocol Validation**

   * HTTP = High Risk
   * HTTPS = Further analysis

7. **Final Scoring Engine**

   * Combines:

     * Reputation
     * Protocol
     * AI confidence

8. **Output**

   * Risk score
   * Verdict (Safe / Suspicious)
   * Explanation

---

## 🏗️ Tech Stack

### 🔹 Frontend

* HTML + Tailwind CSS
* Glassmorphism + Aurora UI
* JavaScript (Vanilla)

### 🔹 Backend

* Flask (Python)

### 🔹 AI / NLP

* Hugging Face Transformers
* DistilBERT (Phishing Detection)

### 🔹 APIs

* Gmail API (OAuth 2.0)
* WHOIS / SSL Lookup

### 🔹 Data

* MySQL (threat_history)

---

## 📊 System Architecture

```
User Input → Flask Backend → NLP Model
         ↓
   URL Analyzer → Domain Check → SSL Check
         ↓
     Scoring Engine
         ↓
   MySQL Database
         ↓
   Live Dashboard (SSE)
```

---


---

## ⚙️ Installation

```bash
git clone https://github.com/your-repo/cortexguard-ai.git
cd cortexguard-ai
pip install -r requirements.txt
python app.py
```

---

## 🌐 Run Locally

Open:

```
http://127.0.0.1:5000
```

---

## 🔮 Future Enhancements

* 📱 SMS scam detection
* 🧠 Personalized risk engine
* 🌍 Multi-language detection
* 🧩 Browser extension
* 🤖 Autonomous AI agent integration

---

## 🏆 Unique Selling Points

* Context-aware detection (not just keyword-based)
* Hybrid AI + rule-based system
* Explainable AI decisions
* Multi-channel threat analysis
* Real-time streaming interface

---

