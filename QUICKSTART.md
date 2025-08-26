# 🚀 Quick Start Guide - Advanced URL Phishing Detector

Get up and running in 5 minutes!

## ⚡ Quick Setup

```bash
# 1. Setup environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Test system
python run.py check
```

## 🎯 Quick Usage

### Web Interface (Recommended)
```bash
python run.py web
# Open http://127.0.0.1:8000
```

### Command Line
```bash
# Single URL
python run.py predict "https://example.com"

# Batch analysis
python run.py batch test_urls.txt
```

## 📊 Example Results

```
======================================================================
🔍 ADVANCED URL PHISHING DETECTION RESULT
======================================================================
URL: https://example.com
Decision: ✅ LEGIT
Score: 0.050
Confidence: HIGH
Domain Age: 365 days
SSL Valid: ✅ Yes
Response Time: 0.15s
======================================================================
```

## 🔧 Key Features

- ✅ **SSL Certificate Validation**
- ✅ **Domain Age Analysis** 
- ✅ **Threat Intelligence**
- ✅ **Real-time Analysis**
- ✅ **Batch Processing**
- ✅ **Smart Caching**

## 🆘 Need Help?

```bash
python run.py info    # System information
python run.py check   # System status
```

---

**Ready to detect phishing URLs with advanced AI! 🛡️**

