# 🔍 Advanced URL Phishing Detector - AI-Powered Security Tool

An advanced, feature-rich AI-powered tool for detecting phishing URLs with real-time analysis, threat intelligence, and comprehensive security features.

## 🚀 Quick Setup (5 minutes)

```bash
# 1. Clone and setup
git clone <repository-url>
cd url-phishing-detector

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Test the system
python run.py check
python run.py info

# 5. Start using!
python run.py web          # Web interface
python run.py predict "https://example.com"  # CLI analysis
```

## ✨ Advanced Features

- **🤖 Advanced AI Analysis**: Sophisticated machine learning algorithms for accurate detection
- **🔒 SSL Certificate Validation**: Real-time SSL certificate verification
- **📅 Domain Age Analysis**: WHOIS lookup for domain registration age
- **⚡ Response Time Analysis**: Performance and connectivity testing
- **🛡️ Threat Intelligence**: Integration with security databases
- **💾 Intelligent Caching**: Fast repeated analysis with result caching
- **🌐 Enhanced Web Interface**: Modern, responsive web application
- **📊 Batch Processing**: Analyze multiple URLs with detailed reporting
- **📈 Real-time Statistics**: Live analysis metrics and insights

## 📖 Usage

### Web Interface

Start the advanced web server:
```bash
python run.py web
```

Then open your browser and go to: `http://127.0.0.1:8000`

**Enhanced Web Features:**
- Real-time analysis with progress indicators
- Detailed security reports
- Interactive threat visualization
- API documentation at `/docs`

### Command Line Interface

#### Single URL Analysis
```bash
python run.py predict "https://example.com"
```

#### Batch Analysis
Create a text file with URLs (one per line) and run:
```bash
python run.py batch urls.txt
```

#### Direct CLI Usage
```bash
# Single URL with advanced analysis
python app/cli.py "https://example.com"

# Batch analysis with detailed reporting
python app/cli.py --batch urls.txt
```

## 🔧 Advanced Analysis Features

### Real-time Security Checks:
- **SSL Certificate Validation**: Verifies certificate authenticity and expiration
- **Domain Age Analysis**: Checks domain registration date for suspicious new domains
- **Response Time Testing**: Measures server response time for performance analysis
- **Threat Intelligence**: Cross-references with known malicious patterns
- **Redirect Analysis**: Detects suspicious redirect chains
- **URL Shortener Detection**: Identifies potentially dangerous shortened URLs

### AI Scoring Algorithm:
The advanced AI uses multiple weighted factors:

**Critical Risk Factors (High Weight):**
- IP addresses instead of domains (0.4 points)
- @ symbols in URLs (0.35 points)
- Invalid SSL certificates (0.3 points)

**High Risk Factors:**
- Excessive subdomains (0.25 points)
- No HTTPS (0.25 points)
- Redirect keywords (0.2 points)
- URL shorteners (0.15 points)

**Medium Risk Factors:**
- Suspicious keywords (0.1 points)
- Hyphens/underscores in domains (0.1 points)
- Long URLs (0.1 points)

**Domain Analysis:**
- New domains (< 30 days: 0.2 points)
- Recent domains (< 90 days: 0.1 points)

### Scoring System:
- **0.0 - 0.1**: LEGIT (Safe) ✅
- **0.1 - 0.3**: SUSPICIOUS (Low Risk) ⚠️
- **0.3 - 0.5**: SUSPICIOUS (Medium Risk) ⚠️
- **0.5 - 0.7**: PHISHING (High Risk) 🚨
- **0.7 - 1.0**: PHISHING (Very High Risk) 🚨

## 📁 Project Structure

```
url-phishing-detector/
├── app/
│   ├── cli.py              # Advanced CLI interface
│   ├── api.py              # Enhanced web API
│   └── web/
│       ├── templates/      # HTML templates
│       └── static/         # Static files
├── run.py                  # Main runner script
├── requirements.txt        # Python dependencies
├── test_urls.txt          # Sample URLs for testing
└── README.md              # This file
```

## 🛠️ API Endpoints

### Web Interface
- `GET /` - Enhanced web interface
- `POST /predict` - Advanced form-based URL analysis
- `POST /api/predict` - JSON API endpoint
- `POST /api/batch` - Batch analysis endpoint
- `GET /api/cache` - Cache information
- `DELETE /api/cache` - Clear analysis cache
- `GET /api/stats` - Analysis statistics
- `GET /health` - Enhanced health check

### Example API Usage
```bash
# Single URL analysis
curl -X POST "http://localhost:8000/api/predict" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=https://example.com"

# Batch analysis
curl -X POST "http://localhost:8000/api/batch" \
     -H "Content-Type: application/json" \
     -d '["https://example.com", "https://suspicious-site.com"]'

# Get statistics
curl "http://localhost:8000/api/stats"
```

## 📊 Enhanced Output Example

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

🔍 Analysis Reasons:
  1. Contains hyphens in domain
======================================================================
```

## 🔒 Security Features

- **Multi-layered Analysis**: Combines multiple detection methods
- **Real-time Validation**: Live SSL and domain checks
- **Threat Intelligence**: Integration with security databases
- **Intelligent Caching**: Prevents redundant analysis
- **Comprehensive Logging**: Detailed analysis trails
- **Rate Limiting**: Prevents abuse and ensures performance

## 🚀 Performance Features

- **Async Processing**: Non-blocking concurrent analysis
- **Smart Caching**: Instant results for previously analyzed URLs
- **Batch Optimization**: Efficient processing of multiple URLs
- **Memory Management**: Optimized resource usage
- **Error Handling**: Graceful failure recovery

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is for educational and research purposes. While it uses advanced AI analysis, it should not be the sole method for determining if a URL is malicious. Always use multiple security measures and common sense when dealing with suspicious links.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the system status: `python run.py check`
2. View system information: `python run.py info`
3. Ensure all dependencies are installed
4. Verify URL format is correct
5. Check the logs for error messages

## 🔄 Version History

- **v2.0.0**: Advanced features, SSL validation, threat intelligence
- **v1.0.0**: Basic AI-powered detection

---

**Made with ❤️ for cybersecurity awareness and protection**
