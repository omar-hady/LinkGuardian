#!/usr/bin/env python3
"""
Advanced URL Phishing Detector CLI
Advanced AI-powered tool for detecting phishing URLs with enhanced features
"""

import argparse
import json
import os
import sys
import requests
import tldextract
from urllib.parse import urlparse
import re
import socket
import ssl
import whois
from datetime import datetime
import time

def extract_url_features(url):
    """Extract advanced features from URL for AI analysis"""
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Extra heuristics for better sensitivity
        def shannon_entropy(s: str) -> float:
            if not s:
                return 0.0
            from math import log2
            freqs = {}
            for ch in s:
                freqs[ch] = freqs.get(ch, 0) + 1
            n = len(s)
            return -sum((c/n) * log2(c/n) for c in freqs.values())

        suspicious_tlds = {'zip','mov','country','click','gq','ml','ga','cf','tk','xyz','top','work','support','buzz','rest','cam','guru','kim'}

        domain = extracted.domain or ''
        suffix = extracted.suffix or ''
        
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'subdomain_count': len([x for x in extracted.subdomain.split('.') if x]) if extracted.subdomain else 0,
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
            'entropy_domain': shannon_entropy(domain),
            'entropy_path': shannon_entropy(parsed.path),
        }
        
        return features, parsed, extracted
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None, None, None

def check_ssl_certificate(hostname: str, port: int = 443):
    """Check SSL certificate validity for a hostname.
    Returns: 1 (valid), 0 (invalid), None (unknown/unreachable)
    """
    if not hostname:
        return None
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                if not not_after:
                    return 0
                try:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                except Exception:
                    # Different locales/timezones formats may appear; if we can't parse, don't penalize
                    return None
                return 1 if expiry > datetime.now() else 0
    except ssl.SSLCertVerificationError:
        return 0
    except Exception:
        # Network/DNS/timeouts or other errors => unknown
        return None

def get_domain_age(domain):
    """Get domain registration age in days"""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            age_days = (datetime.now() - creation_date).days
            return max(0, age_days)
    except:
        pass
    return 0

def test_url_response(url, timeout=5):
    """Test URL response time and status"""
    try:
        start_time = time.time()
        response = requests.get(url, timeout=timeout, allow_redirects=False)
        response_time = time.time() - start_time
        return response_time, response.status_code
    except:
        return 0, 0

def analyze_url_with_advanced_ai(url):
    """Analyze URL using advanced AI-based heuristics"""
    features, parsed, extracted = extract_url_features(url)
    if not features:
        return None
    
    print("🔍 Analyzing URL features...")
    
    # Advanced checks
    if extracted and extracted.domain:
        hostname = parsed.hostname
        # Only check SSL for HTTPS and non-IP hostnames
        if features['has_https'] and hostname and not features['has_ip']:
            print("  📋 Checking SSL certificate...")
            features['ssl_valid'] = check_ssl_certificate(hostname)
        
        print("  📅 Checking domain age...")
        features['domain_age_days'] = get_domain_age(extracted.domain)
        
        print("  ⚡ Testing response time...")
        response_time, status_code = test_url_response(url)
        features['response_time'] = response_time
    
    # Advanced AI-based scoring algorithm (more sensitive)
    score = 0.0
    reasons = []
    
    # Critical risk factors (high weight)
    if features['has_ip']:
        score += 0.4
        reasons.append("🚨 URL contains IP address instead of domain")
    
    if features['has_at_symbol']:
        score += 0.35
        reasons.append("🚨 Contains @ symbol (common in phishing)")
    
    # Penalize SSL only when explicitly invalid (not when unknown)
    if features['has_https'] and features['ssl_valid'] == 0:
        score += 0.3
        reasons.append("🚨 Invalid SSL certificate")
    
    # High risk factors
    if features.get('tld_suspicious'):
        score += 0.25
        reasons.append("⚠️ Suspicious top-level domain")
    
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
    
    # Normalize score to 0-1 range
    score = min(score, 1.0)
    
    # Determine decision with confidence (lowered thresholds)
    if score > 0.6:
        decision = "PHISHING"
        confidence = "VERY HIGH"
        emoji = "🚨"
    elif score > 0.45:
        decision = "PHISHING"
        confidence = "HIGH"
        emoji = "🚨"
    elif score > 0.25:
        decision = "SUSPICIOUS"
        confidence = "MEDIUM"
        emoji = "⚠️"
    elif score > 0.08:
        decision = "SUSPICIOUS"
        confidence = "LOW"
        emoji = "⚠️"
    else:
        decision = "LEGIT"
        confidence = "HIGH"
        emoji = "✅"
    
    return {
        'url': url,
        'decision': decision,
        'score': score,
        'confidence': confidence,
        'emoji': emoji,
        'reasons': reasons[:8],
        'features': features,
        'domain_age_days': features['domain_age_days'],
        'ssl_valid': features['ssl_valid'],
        'response_time': features['response_time']
    }

def print_result(result):
    """Print enhanced prediction result"""
    if not result:
        return
    
    print("\n" + "="*70)
    print("🔍 ADVANCED URL PHISHING DETECTION RESULT")
    print("="*70)
    print(f"URL: {result['url']}")
    print(f"Decision: {result['emoji']} {result['decision']}")
    print(f"Score: {result['score']:.3f}")
    print(f"Confidence: {result['confidence']}")
    
    if result['domain_age_days'] > 0:
        print(f"Domain Age: {result['domain_age_days']} days")
    
    # Improved SSL output
    if result['ssl_valid'] is None:
        print("SSL Valid: ❓ Unknown (skipped or unreachable)")
    else:
        print(f"SSL Valid: {'✅ Yes' if result['ssl_valid'] else '❌ No'}")
    
    if result['response_time'] > 0:
        print(f"Response Time: {result['response_time']:.2f}s")
    
    if result['reasons']:
        print(f"\n🔍 Analysis Reasons:")
        for i, reason in enumerate(result['reasons'], 1):
            print(f"  {i}. {reason}")
    
    print("="*70)

def analyze_single_url(url):
    """Analyze a single URL with enhanced features"""
    print(f"🔍 Analyzing URL: {url}")
    result = analyze_url_with_advanced_ai(url)
    print_result(result)
    return result

def analyze_batch_urls(file_path):
    """Analyze URLs from a file with enhanced features"""
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"📁 Analyzing {len(urls)} URLs from {file_path}")
        print("="*70)
        
        results = []
        for i, url in enumerate(urls, 1):
            print(f"\n{i}/{len(urls)}: {url}")
            result = analyze_url_with_advanced_ai(url)
            if result:
                results.append(result)
                print_result(result)
        
        # Enhanced summary
        phishing_count = sum(1 for r in results if r['decision'] == 'PHISHING')
        suspicious_count = sum(1 for r in results if r['decision'] == 'SUSPICIOUS')
        legit_count = sum(1 for r in results if r['decision'] == 'LEGIT')
        
        avg_score = sum(r['score'] for r in results) / len(results) if results else 0
        
        print(f"\n📊 ENHANCED SUMMARY:")
        print(f"Total URLs: {len(results)}")
        print(f"🚨 Phishing: {phishing_count}")
        print(f"⚠️  Suspicious: {suspicious_count}")
        print(f"✅ Legitimate: {legit_count}")
        print(f"Average Risk Score: {avg_score:.3f}")
        
        # Risk assessment
        if avg_score > 0.5:
            print("🔴 Overall Risk Level: HIGH")
        elif avg_score > 0.2:
            print("🟡 Overall Risk Level: MEDIUM")
        else:
            print("🟢 Overall Risk Level: LOW")
        
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
    except Exception as e:
        print(f"❌ Error reading file: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced AI-powered URL Phishing Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python app/cli.py https://example.com
  python app/cli.py --batch urls.txt
  python app/cli.py --detailed https://example.com
        """
    )
    
    parser.add_argument('url', nargs='?', help='URL to analyze')
    parser.add_argument('--batch', help='File containing URLs to analyze')
    parser.add_argument('--detailed', action='store_true', help='Show detailed analysis')
    
    args = parser.parse_args()
    
    if args.batch:
        analyze_batch_urls(args.batch)
    elif args.url:
        analyze_single_url(args.url)
    else:
        print("❌ Please provide a URL or use --batch option")
        parser.print_help()

if __name__ == "__main__":
    main()
