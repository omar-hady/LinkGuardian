"""
Advanced URL Phishing Detector API
Advanced AI-powered tool for detecting phishing URLs with enhanced features
"""

from fastapi import FastAPI, Request, Form, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import json
import re
import tldextract
from urllib.parse import urlparse
from typing import Dict, Any, List
import socket
import ssl
import whois
from datetime import datetime
import time
import asyncio
import aiohttp
from collections import defaultdict
from time import time as now
import sqlite3
from difflib import SequenceMatcher

try:
    from bs4 import BeautifulSoup  # type: ignore
    HAVE_BS4 = True
except Exception:
    BeautifulSoup = None  # type: ignore
    HAVE_BS4 = False

# Simple in-memory rate-limiter per IP
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 20     # requests per window
rate_limit_state = defaultdict(list)  # ip -> timestamps

app = FastAPI(
    title="Advanced URL Phishing Detector",
    description="Advanced AI-powered tool to detect phishing URLs with real-time analysis",
    version="2.0.0"
)

# Security headers middleware & simple request logging
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        # Note: For CSP and HSTS use a reverse proxy in production
        return response

app.add_middleware(SecurityHeadersMiddleware)

templates = Jinja2Templates(directory="app/web/templates")
# Serve static assets (CSS, images)
app.mount("/static", StaticFiles(directory="app/web/static"), name="static")

# Cache for storing analysis results
analysis_cache = {}
threat_intelligence = defaultdict(list)

# External threat feed caches
threat_url_set = set()
threat_domain_set = set()

# SQLite helpers
DB_PATH = "phishing_detector.db"

def get_db_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                decision TEXT,
                score REAL,
                confidence TEXT,
                ts TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_feed (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                value TEXT UNIQUE,
                source TEXT,
                ts TEXT
            )
            """
        )
        conn.commit()

async def refresh_threat_feeds_periodically():
    while True:
        try:
            await fetch_threat_feeds()
        except Exception as e:
            print(f"⚠️ Threat feed refresh error: {e}")
        await asyncio.sleep(60 * 30)

async def fetch_threat_feeds():
    global threat_url_set, threat_domain_set
    sources = [
        ("urlhaus", "https://urlhaus.abuse.ch/downloads/text_online/"),
        ("openphish", "https://openphish.com/feed.txt"),
    ]
    urls = set()
    domains = set()
    async with aiohttp.ClientSession() as session:
        for name, feed_url in sources:
            try:
                async with session.get(feed_url, timeout=20) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            urls.add(line)
                            try:
                                p = urlparse(line)
                                if p.hostname:
                                    domains.add(p.hostname.lower())
                            except Exception:
                                pass
            except Exception:
                continue
    threat_url_set = urls
    threat_domain_set = domains
    ts = datetime.now().isoformat()
    with get_db_conn() as conn:
        c = conn.cursor()
        for u in list(urls)[:5000]:
            try:
                c.execute("INSERT OR IGNORE INTO threat_feed(kind,value,source,ts) VALUES(?,?,?,?)", ("url", u, "feed", ts))
            except Exception:
                pass
        for d in list(domains)[:5000]:
            try:
                c.execute("INSERT OR IGNORE INTO threat_feed(kind,value,source,ts) VALUES(?,?,?,?)", ("domain", d, "feed", ts))
            except Exception:
                pass
        conn.commit()

def extract_url_features(url):
    """Extract advanced features from URL for AI analysis"""
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Helper signals
        def shannon_entropy(s: str) -> float:
            if not s:
                return 0.0
            from math import log2
            freqs = defaultdict(int)
            for ch in s:
                freqs[ch] += 1
            n = len(s)
            return -sum((c/n) * log2(c/n) for c in freqs.values())

        def is_idn(text: str) -> bool:
            try:
                text.encode('ascii')
                return False
            except Exception:
                return True

        suspicious_tlds = {
            'zip','mov','country','click','gq','ml','ga','cf','tk','xyz','top','work','support','buzz','rest','cam','guru','kim'
        }

        domain = extracted.domain or ''
        suffix = extracted.suffix or ''
        subdomain = extracted.subdomain or ''

        entropy_domain = shannon_entropy(domain)
        entropy_path = shannon_entropy(parsed.path)

        digit_count = sum(ch.isdigit() for ch in domain)
        hyphen_count = domain.count('-')
        pct_encoding = '%' in url
        mixed_scripts = is_idn(url)

        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'subdomain_count': len([x for x in subdomain.split('.') if x]) if subdomain else 0,
            'path_length': len(parsed.path),
            'query_length': len(parsed.query),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_ip': 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain) else 0,
            'has_at_symbol': 1 if '@' in url else 0,
            'has_hyphen': 1 if '-' in domain else 0,
            'has_underscore': 1 if '_' in domain else 0,
            'has_suspicious_keywords': 1 if any(keyword in url.lower() for keyword in [
                'login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm', 'bank', 'paypal', 'amazon'
            ]) else 0,
            'has_redirect': 1 if any(keyword in url.lower() for keyword in ['redirect', 'goto', 'link']) else 0,
            'has_shortener': 1 if any(keyword in url.lower() for keyword in ['bit.ly', 'tinyurl', 'goo.gl']) else 0,
            'tld_suspicious': 1 if suffix.lower() in suspicious_tlds else 0,
            'entropy_domain': entropy_domain,
            'entropy_path': entropy_path,
            'digit_ratio_domain': (digit_count / max(1, len(domain))),
            'hyphen_count': hyphen_count,
            'percent_encoding': 1 if pct_encoding else 0,
            'idn_or_mixed': 1 if mixed_scripts else 0,
            'suspicious_filename': 1 if re.search(r'(login|verify|update|secure|payment)\.(php|asp|aspx|jsp)$', parsed.path.lower()) else 0,
            'data_or_js_protocol': 1 if url.lower().startswith(('data:', 'javascript:')) else 0,
            'domain_age_days': 0,
            'ssl_valid': None,
            'response_time': 0,
            'redirect_count': 0,
            'has_popup': 0,
            'has_iframe': 0,
        }
        
        return features, parsed, extracted
    except Exception as e:
        return None, None, None

async def check_ssl_certificate_async(hostname: str, port: int = 443):
    """Check SSL certificate validity asynchronously for a hostname.
    Returns: 1 (valid), 0 (invalid), None (unknown/unreachable)
    """
    if not hostname:
        return None
    try:
        # Quick TLS handshake to ensure reachability
        context = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=context),
            timeout=5.0
        )
        writer.close()
        await writer.wait_closed()
    except ssl.SSLCertVerificationError:
        return 0
    except Exception:
        return None

    # Parse certificate details using blocking socket briefly
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                san = cert.get('subjectAltName', [])
                san_hosts = [v for (k, v) in san if k == 'DNS'] if san else []
                san_match = hostname in san_hosts or any(h.startswith('*.') and hostname.endswith(h[2:]) for h in san_hosts)
                expiry_ok = True
                if not_after:
                    try:
                        exp_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        expiry_ok = (exp_dt - datetime.now()).days > 7
                    except Exception:
                        pass
                return 1 if san_match and expiry_ok else 0
    except ssl.SSLCertVerificationError:
        return 0
    except Exception:
        return None

async def get_domain_age_async(domain):
    """Get domain registration age in days asynchronously"""
    try:
        # This would need an async WHOIS library, but for now we'll use a simple approach
        return 365  # Default to 1 year for demo
    except:
        return 0

async def test_url_response_async(url, timeout=5):
    """Test URL response time and status asynchronously"""
    try:
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            async with session.get(url, timeout=timeout, allow_redirects=False) as response:
                response_time = time.time() - start_time
                return response_time, response.status
    except:
        return 0, 0

async def check_threat_intelligence(domain):
    """Check against threat intelligence sources"""
    # This would integrate with real threat intelligence APIs
    # For now, we'll simulate some checks
    suspicious_patterns = [
        'malware', 'phish', 'scam', 'fake', 'clone'
    ]
    
    for pattern in suspicious_patterns:
        if pattern in domain.lower():
            return True, f"Domain contains suspicious keyword: {pattern}"
    
    return False, "No known threats detected"

async def fetch_page_signals(url: str, timeout: int = 8):
    """Fetch limited page content safely and extract signals (no JS execution)."""
    signals = {
        'title': '',
        'has_login_form': 0,
        'input_password_fields': 0,
        'external_scripts': 0,
        'iframes': 0,
        'forms': 0,
        'meta_generator': '',
    }
    if not HAVE_BS4:
        return signals
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                if resp.status >= 400 or resp.content_type not in ("text/html", "application/xhtml+xml"):
                    return signals
                text = await resp.text(errors='ignore')
                soup = BeautifulSoup(text, 'html.parser')
                if soup.title and soup.title.string:
                    signals['title'] = soup.title.string[:120]
                inputs = soup.find_all('input')
                pw = [i for i in inputs if (i.get('type') or '').lower() == 'password']
                signals['input_password_fields'] = len(pw)
                forms = soup.find_all('form')
                signals['forms'] = len(forms)
                if any(pw):
                    signals['has_login_form'] = 1
                scripts = soup.find_all('script', src=True)
                signals['external_scripts'] = len(scripts)
                ifr = soup.find_all('iframe')
                signals['iframes'] = len(ifr)
                meta_gen = soup.find('meta', attrs={'name': 'generator'})
                if meta_gen and meta_gen.get('content'):
                    signals['meta_generator'] = meta_gen['content'][:80]
    except Exception:
        return signals
    return signals

async def analyze_url_with_advanced_ai_async(url, deep: bool = False):
    """Analyze URL using advanced AI-based heuristics asynchronously"""
    features, parsed, extracted = extract_url_features(url)
    if not features:
        return None

    # Check threat feeds (no user-facing reason; used as hidden signal)
    feed_matched = False
    try:
        host = parsed.hostname.lower() if parsed and parsed.hostname else None
        if host and (url in threat_url_set or host in threat_domain_set):
            feed_matched = True
    except Exception:
        pass

    # Run advanced checks concurrently
    tasks = []
    if extracted and extracted.domain:
        hostname = parsed.hostname
        # Only check SSL for HTTPS and non-IP hostnames
        if features['has_https'] and hostname and not features['has_ip']:
            tasks.append(check_ssl_certificate_async(hostname))
        tasks.extend([
            get_domain_age_async(extracted.domain),
            test_url_response_async(url),
            check_threat_intelligence(extracted.domain)
        ])
        if deep:
            tasks.append(fetch_page_signals(url))

    deep_signals = None
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        idx = 0
        if features['has_https'] and parsed.hostname and not features['has_ip']:
            ssl_res = results[idx] if not isinstance(results[idx], Exception) else None
            features['ssl_valid'] = ssl_res
            idx += 1
        domain_age_res = results[idx] if not isinstance(results[idx], Exception) else 0
        features['domain_age_days'] = domain_age_res
        idx += 1
        resp_res = results[idx] if not isinstance(results[idx], Exception) else (0, 0)
        response_time, _ = resp_res if isinstance(resp_res, tuple) else (0, 0)
        features['response_time'] = response_time
        idx += 1
        ti_res = results[idx] if not isinstance(results[idx], Exception) else (False, "")
        threat_detected, threat_info = ti_res if isinstance(ti_res, tuple) else (False, "")
        idx += 1
        if deep and idx < len(results):
            deep_signals = results[idx] if isinstance(results[idx], dict) else None

    # Scoring
    score = 0.0
    reasons = []

    # Hidden boost if threat feeds matched
    if feed_matched:
        score += 0.35

    # Critical risk factors (high weight)
    if features['has_ip']:
        score += 0.4
        reasons.append("🚨 URL contains IP address instead of domain")

    if features['has_at_symbol']:
        score += 0.35
        reasons.append("🚨 Contains @ symbol (common in phishing)")

    if features.get('data_or_js_protocol'):
        score += 0.4
        reasons.append("🚨 Uses data: or javascript: scheme")

    # Penalize SSL only when explicitly invalid (not when unknown)
    if features['has_https'] and features['ssl_valid'] == 0:
        score += 0.3
        reasons.append("🚨 Invalid SSL certificate")

    # High risk factors
    if features.get('tld_suspicious'):
        score += 0.25
        reasons.append("⚠️ Suspicious top-level domain")

    # Brand homograph / similarity
    try:
        brands = ['paypal','apple','amazon','microsoft','facebook','instagram','google','binance','blockchain','meta','whatsapp','tiktok']
        label = (extracted.domain or '').lower()
        if label:
            best = max(SequenceMatcher(a=label, b=b).ratio() for b in brands)
            if best >= 0.75 and label not in brands:
                score += 0.2
                reasons.append("⚠️ Domain similar to a known brand")
    except Exception:
        pass

    if features.get('idn_or_mixed'):
        score += 0.2
        reasons.append("⚠️ Internationalized or mixed-script URL")

    if features['subdomain_count'] >= 4:
        score += 0.25
        reasons.append("⚠️ Excessive number of subdomains")
    elif features['subdomain_count'] >= 3:
        score += 0.15
        reasons.append("⚠️ High number of subdomains")

    if features['url_length'] > 150:
        score += 0.2
        reasons.append("⚠️ Unusually long URL")
    elif features['url_length'] > 100:
        score += 0.1
        reasons.append("⚠️ Long URL")

    if not features['has_https']:
        score += 0.25
        reasons.append("⚠️ Does not use HTTPS")

    if features['has_redirect']:
        score += 0.2
        reasons.append("⚠️ Contains redirect keywords")

    if features['has_shortener']:
        score += 0.15
        reasons.append("⚠️ Uses URL shortener")

    # Medium risk factors
    if features['has_hyphen']:
        score += 0.1
        reasons.append("⚠️ Contains hyphens in domain")

    if features['has_underscore']:
        score += 0.1
        reasons.append("⚠️ Contains underscores in domain")

    if features['has_suspicious_keywords']:
        score += 0.1
        reasons.append("⚠️ Contains suspicious keywords")

    if features.get('suspicious_filename'):
        score += 0.1
        reasons.append("⚠️ Suspicious filename (e.g., login.php)")

    if features['domain_length'] > 25:
        score += 0.05
        reasons.append("⚠️ Very long domain name")
    elif features['domain_length'] > 20:
        score += 0.03
        reasons.append("⚠️ Long domain name")

    if features['path_length'] > 80:
        score += 0.08
        reasons.append("⚠️ Very long URL path")
    elif features['path_length'] > 50:
        score += 0.05
        reasons.append("⚠️ Long URL path")

    if features.get('digit_ratio_domain', 0) > 0.3:
        score += 0.08
        reasons.append("⚠️ Many digits in domain")

    if features.get('hyphen_count', 0) >= 3:
        score += 0.06
        reasons.append("⚠️ Multiple hyphens in domain")

    if features.get('percent_encoding'):
        score += 0.05
        reasons.append("⚠️ Percent-encoding present")

    if features.get('entropy_domain', 0) > 3.5:
        score += 0.08
        reasons.append("⚠️ High domain randomness")

    if features.get('entropy_path', 0) > 4.0:
        score += 0.05
        reasons.append("⚠️ High path randomness")

    # Domain age analysis
    if features['domain_age_days'] < 30:
        score += 0.2
        reasons.append("🚨 Very new domain (< 30 days)")
    elif features['domain_age_days'] < 90:
        score += 0.1
        reasons.append("⚠️ New domain (< 90 days)")

    # Response time analysis
    if features['response_time'] > 3:
      score += 0.05
      reasons.append("⚠️ Slow response time")

    # Threat intelligence (legacy simulated)
    if 'threat_detected' in locals() and threat_detected:
        score += 0.3
        reasons.append(f"🚨 {threat_info}")

    # Normalize, thresholds and result
    score = min(score, 1.0)
    if score > 0.6:
        decision = "PHISHING"; confidence = "VERY HIGH"; emoji = "🚨"; color = "danger"
    elif score > 0.45:
        decision = "PHISHING"; confidence = "HIGH"; emoji = "🚨"; color = "danger"
    elif score > 0.25:
        decision = "SUSPICIOUS"; confidence = "MEDIUM"; emoji = "⚠️"; color = "warning"
    elif score > 0.08:
        decision = "SUSPICIOUS"; confidence = "LOW"; emoji = "⚠️"; color = "warning"
    else:
        decision = "LEGIT"; confidence = "HIGH"; emoji = "✅"; color = "success"

    result = {
        'url': url,
        'decision': decision,
        'score': score,
        'confidence': confidence,
        'emoji': emoji,
        'color': color,
        'reasons': reasons[:8],
        'features': features,
        'domain_age_days': features['domain_age_days'],
        'ssl_valid': features['ssl_valid'],
        'response_time': features['response_time'],
        'analysis_timestamp': datetime.now().isoformat(),
        'deep': bool(deep),
        'page': deep_signals or {},
        'feed_matched': feed_matched
    }
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO analyses(url,decision,score,confidence,ts) VALUES(?,?,?,?,?)",
                      (url, result['decision'], float(result['score']), result['confidence'], result['analysis_timestamp']))
            conn.commit()
    except Exception:
        pass
    return result

def validate_url(url: str) -> bool:
    """Validate URL format"""
    if not url or len(url.strip()) == 0:
        return False
    
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(url_pattern.match(url.strip()))

async def background_analysis(url: str):
    """Background task for detailed analysis"""
    result = await analyze_url_with_advanced_ai_async(url)
    if result:
        analysis_cache[url] = result

def get_db_summary():
    """Return summary counts from DB if available; fallback to cache."""
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(1) FROM analyses")
            row = c.fetchone()
            if row and row[0] is not None:
                total = int(row[0])
                return {"total_checks": total, "cache_size": len(analysis_cache)}
    except Exception:
        pass
    return {"total_checks": len(analysis_cache), "cache_size": len(analysis_cache)}

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    print("🚀 Starting Advanced URL Phishing Detector...")
    print("🔧 Loading threat intelligence...")
    init_db()
    try:
        asyncio.create_task(refresh_threat_feeds_periodically())
    except Exception:
        pass
    print("✅ System ready!")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Enhanced web interface"""
    stats = get_db_summary()
    return templates.TemplateResponse("index.html", {"request": request, "result": None, "stats": stats})

@app.get("/how-it-works", response_class=HTMLResponse)
async def how_it_works(request: Request):
    """How it works page"""
    return templates.TemplateResponse("how.html", {"request": request})

@app.get("/cli", response_class=HTMLResponse)
async def cli_page(request: Request):
    """CLI usage page"""
    return templates.TemplateResponse("cli.html", {"request": request})

@app.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request):
    """Stats dashboard page backed by SQLite if populated, otherwise in-memory cache"""
    total = 0
    phishing = 0
    suspicious = 0
    legit = 0
    avg = 0.0
    recent = []
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(1) FROM analyses")
            row = c.fetchone()
            if row and row[0] > 0:
                total = row[0]
                c.execute("SELECT decision, COUNT(1) FROM analyses GROUP BY decision")
                for d, cnt in c.fetchall():
                    if d == 'PHISHING': phishing = cnt
                    elif d == 'SUSPICIOUS': suspicious = cnt
                    elif d == 'LEGIT': legit = cnt
                c.execute("SELECT AVG(score) FROM analyses")
                avg_row = c.fetchone()
                avg = float(avg_row[0]) if avg_row and avg_row[0] is not None else 0.0
                c.execute("SELECT url, decision, score, ts FROM analyses ORDER BY id DESC LIMIT 10")
                for u, d, s, ts in c.fetchall():
                    recent.append({
                        'url': u,
                        'decision': d,
                        'score': float(s),
                        'emoji': '🚨' if d=='PHISHING' else ('⚠️' if d=='SUSPICIOUS' else '✅'),
                        'analysis_timestamp': ts
                    })
    except Exception:
        pass

    if total == 0:
        # fallback to cache
        decisions = [r['decision'] for r in analysis_cache.values()]
        scores = [r['score'] for r in analysis_cache.values()]
        total = len(decisions)
        phishing = decisions.count('PHISHING')
        suspicious = decisions.count('SUSPICIOUS')
        legit = decisions.count('LEGIT')
        avg = sum(scores)/len(scores) if scores else 0
        recent = list(analysis_cache.values())[-10:]

    stats = {
        'total_analyses': total,
        'phishing_count': phishing,
        'suspicious_count': suspicious,
        'legit_count': legit,
        'average_score': avg,
        'recent': recent,
    }
    return templates.TemplateResponse("stats.html", {"request": request, "stats": stats})

@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})

@app.post("/predict", response_class=HTMLResponse)
async def predict_form(request: Request, url: str = Form(...)):
    try:
        client_ip = request.client.host if request.client else 'unknown'
        timestamps = rate_limit_state[client_ip]
        cutoff = now() - RATE_LIMIT_WINDOW
        rate_limit_state[client_ip] = [t for t in timestamps if t > cutoff]
        if len(rate_limit_state[client_ip]) >= RATE_LIMIT_MAX:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": "Rate limit exceeded. Please wait a bit and try again."
            })
        rate_limit_state[client_ip].append(now())
        if not validate_url(url):
            return templates.TemplateResponse("index.html", {"request": request, "error": "Invalid URL format. Please enter a valid URL starting with http:// or https://"})
        # Always deep analyze (no caching for content-sensitive results)
        result = await analyze_url_with_advanced_ai_async(url, deep=True)
        if not result:
            return templates.TemplateResponse("index.html", {"request": request, "error": "Failed to analyze URL. Please try again."})
        stats = get_db_summary()
        return templates.TemplateResponse("index.html", {"request": request, "result": result, "stats": stats})
    except Exception as e:
        return templates.TemplateResponse("index.html", {"request": request, "error": f"Error analyzing URL: {str(e)}"})

@app.post("/api/predict")
async def predict_api(url: str = Form(...)):
    try:
        client_ip = 'api-client'
        timestamps = rate_limit_state[client_ip]
        cutoff = now() - RATE_LIMIT_WINDOW
        rate_limit_state[client_ip] = [t for t in timestamps if t > cutoff]
        if len(rate_limit_state[client_ip]) >= RATE_LIMIT_MAX:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        rate_limit_state[client_ip].append(now())
        if not validate_url(url):
            raise HTTPException(status_code=400, detail="Invalid URL format")
        # Always deep analyze
        result = await analyze_url_with_advanced_ai_async(url, deep=True)
        if not result:
            raise HTTPException(status_code=500, detail="Failed to analyze URL")
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")

@app.post("/api/batch")
async def batch_predict_api(urls: List[str]):
    """Batch prediction API endpoint"""
    try:
        if not urls or len(urls) > 50:  # Limit batch size
            raise HTTPException(status_code=400, detail="Invalid number of URLs (max 50)")
        
        results = []
        for url in urls:
            if not validate_url(url):
                results.append({
                    "url": url,
                    "error": "Invalid URL format"
                })
                continue
            
            if url in analysis_cache:
                result = analysis_cache[url]
            else:
                result = await analyze_url_with_advanced_ai_async(url)
                if result:
                    analysis_cache[url] = result
            
            if result:
                results.append(result)
            else:
                results.append({
            "url": url, 
                    "error": "Analysis failed"
                })
        
        return JSONResponse(content={
            "results": results,
            "total": len(urls),
            "processed": len([r for r in results if "error" not in r])
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in batch analysis: {str(e)}")

@app.get("/api/cache")
async def get_cache_info():
    """Get cache information"""
    return JSONResponse(content={
        "cache_size": len(analysis_cache),
        "cached_urls": list(analysis_cache.keys())[:10]  # Show first 10
    })

@app.delete("/api/cache")
async def clear_cache():
    """Clear analysis cache"""
    analysis_cache.clear()
    return JSONResponse(content={"message": "Cache cleared successfully"})

@app.get("/health")
async def health_check():
    """Enhanced health check endpoint"""
    return {
            "status": "healthy",
        "service": "Advanced URL Phishing Detector",
        "version": "2.0.0",
        "cache_size": len(analysis_cache),
        "uptime": "running"
    }

@app.get("/api/stats")
async def get_stats():
    """Get analysis statistics (DB if present, else cache)"""
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(1) FROM analyses")
            row = c.fetchone()
            if row and row[0] > 0:
                total = row[0]
                c.execute("SELECT decision, COUNT(1) FROM analyses GROUP BY decision")
                counts = {d: cnt for d, cnt in c.fetchall()}
                c.execute("SELECT AVG(score) FROM analyses")
                avg_row = c.fetchone()
                avg = float(avg_row[0]) if avg_row and avg_row[0] is not None else 0.0
                return JSONResponse(content={
                    'total_analyses': total,
                    'phishing_count': counts.get('PHISHING', 0),
                    'suspicious_count': counts.get('SUSPICIOUS', 0),
                    'legit_count': counts.get('LEGIT', 0),
                    'average_score': avg
                })
    except Exception:
        pass

    if not analysis_cache:
        return JSONResponse(content={'message': 'No analysis data available'})
    decisions = [r['decision'] for r in analysis_cache.values()]
    scores = [r['score'] for r in analysis_cache.values()]
    return JSONResponse(content={
        'total_analyses': len(decisions),
        'phishing_count': decisions.count('PHISHING'),
        'suspicious_count': decisions.count('SUSPICIOUS'),
        'legit_count': decisions.count('LEGIT'),
        'average_score': sum(scores)/len(scores) if scores else 0,
        'high_risk_urls': len([s for s in scores if s > 0.5])
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
