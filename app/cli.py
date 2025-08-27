#!/usr/bin/env python3
"""
Advanced URL Phishing Detector CLI
Advanced AI-powered tool for detecting phishing URLs with enhanced features
"""

import argparse
import json
import os
import sys
import asyncio
import requests
import tldextract
from urllib.parse import urlparse
import re
import socket
import ssl
import whois
from datetime import datetime
import time

try:
    from app.analysis import analyze_url_with_advanced_ai_async
except Exception:
    analyze_url_with_advanced_ai_async = None  # type: ignore

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
    """Analyze URL using shared async analyzer (deeper and more accurate)."""
    if analyze_url_with_advanced_ai_async is None:
        # Fallback to legacy in-file logic if import failed
        return None
    return asyncio.run(analyze_url_with_advanced_ai_async(url, deep=False))

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
    if result.get('features', {}).get('redirect_count', 0) > 0:
        print(f"Redirects: {result['features']['redirect_count']}")
    
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
