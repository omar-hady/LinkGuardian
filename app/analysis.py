"""
Shared advanced URL analysis utilities (async) for CLI and API.
Includes: feature extraction, SSL/WHOIS/RT checks, redirect depth,
IDN/punycode detection, brand similarity, and scoring.
"""

from __future__ import annotations

import re
import ssl
import socket
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, Set
from urllib.parse import urlparse

import tldextract
from difflib import SequenceMatcher

import asyncio
import aiohttp


def validate_url(url: str) -> bool:
    if not url or len(url.strip()) == 0:
        return False
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[[0-9a-fA-F:]+\])'  # IPv6 in brackets
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(url_pattern.match(url.strip()))


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    from math import log2
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def _is_idn_or_mixed(text: str) -> bool:
    try:
        text.encode('ascii')
        return False
    except Exception:
        return True


async def _check_ssl_certificate_async(hostname: str, port: int = 443) -> Optional[int]:
    if not hostname:
        return None
    try:
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


async def _test_url_head_get_async(url: str, timeout: int = 6) -> Tuple[float, int]:
    try:
        async with aiohttp.ClientSession() as session:
            start = asyncio.get_event_loop().time()
            try:
                async with session.head(url, timeout=timeout, allow_redirects=False) as r:
                    end = asyncio.get_event_loop().time()
                    return (end - start), r.status
            except Exception:
                start = asyncio.get_event_loop().time()
                async with session.get(url, timeout=timeout, allow_redirects=False) as r:
                    end = asyncio.get_event_loop().time()
                    return (end - start), r.status
    except Exception:
        return 0.0, 0


async def follow_redirects_async(url: str, max_redirects: int = 4, timeout: int = 6) -> Tuple[str, int]:
    """Follow redirects (HEAD then GET fallback), capped.
    Returns (final_url, redirect_count).
    """
    current = url
    count = 0
    try:
        async with aiohttp.ClientSession() as session:
            while count < max_redirects:
                try:
                    async with session.head(current, timeout=timeout, allow_redirects=False) as r:
                        if 300 <= r.status < 400 and 'Location' in r.headers:
                            loc = r.headers.get('Location')
                            if not loc:
                                break
                            # Absolute or relative
                            parsed = urlparse(current)
                            next_url = loc if '://' in loc else f"{parsed.scheme}://{parsed.netloc}{loc}"
                            current = next_url
                            count += 1
                            continue
                        break
                except Exception:
                    break
    except Exception:
        pass
    return current, count


def extract_url_features(url: str) -> Tuple[Optional[Dict[str, Any]], Any, Any]:
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        domain = extracted.domain or ''
        suffix = extracted.suffix or ''
        subdomain = extracted.subdomain or ''

        domain_entropy = _shannon_entropy(domain)
        path_entropy = _shannon_entropy(parsed.path)

        digit_count = sum(ch.isdigit() for ch in domain)
        hyphen_count = domain.count('-')
        pct_encoding = '%' in url
        mixed_scripts = _is_idn_or_mixed(url)

        suspicious_tlds = {
            'zip','mov','country','click','gq','ml','ga','cf','tk','xyz','top','work','support','buzz','rest','cam','guru','kim','fit','quest','review','download','date'
        }

        ipv4_re = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
        ipv6_re = re.compile(r'^[0-9a-fA-F:]+$')
        host_label = parsed.hostname or domain
        is_ip = 1 if (ipv4_re.match(host_label or '') or ipv6_re.match(host_label or '')) else 0

        features: Dict[str, Any] = {
            'normalized_url': url,
            'url_length': len(url),
            'domain_length': len(domain),
            'subdomain_count': len([x for x in subdomain.split('.') if x]) if subdomain else 0,
            'path_length': len(parsed.path),
            'query_length': len(parsed.query),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_ip': is_ip,
            'has_at_symbol': 1 if '@' in url else 0,
            'has_hyphen': 1 if '-' in domain else 0,
            'has_underscore': 1 if '_' in domain else 0,
            'has_suspicious_keywords': 1 if any(k in url.lower() for k in ['login','signin','account','verify','secure','update','confirm','bank','paypal','amazon']) else 0,
            'has_redirect': 1 if any(k in url.lower() for k in ['redirect','goto','link']) else 0,
            'has_shortener': 1 if any(k in url.lower() for k in ['bit.ly','tinyurl','goo.gl','t.co','ow.ly']) else 0,
            'tld_suspicious': 1 if suffix.lower() in suspicious_tlds else 0,
            'entropy_domain': domain_entropy,
            'entropy_path': path_entropy,
            'digit_ratio_domain': (digit_count / max(1, len(domain))),
            'hyphen_count': hyphen_count,
            'percent_encoding': 1 if pct_encoding else 0,
            'idn_or_mixed': 1 if mixed_scripts else 0,
            'suspicious_filename': 1 if re.search(r'(login|verify|update|secure|payment)\.(php|asp|aspx|jsp)$', parsed.path.lower()) else 0,
            'data_or_js_protocol': 1 if url.lower().startswith(('data:', 'javascript:')) else 0,
            'domain_age_days': 0,
            'ssl_valid': None,
            'response_time': 0.0,
            'redirect_count': 0,
        }
        return features, parsed, extracted
    except Exception:
        return None, None, None


async def analyze_url_with_advanced_ai_async(
    url: str,
    deep: bool = False,
    threat_urls: Optional[Set[str]] = None,
    threat_domains: Optional[Set[str]] = None,
) -> Optional[Dict[str, Any]]:
    features, parsed, extracted = extract_url_features(url)
    if not features:
        return None

    feed_matched = False
    try:
        host = parsed.hostname.lower() if parsed and parsed.hostname else None
        if host and ((threat_urls and url in threat_urls) or (threat_domains and host in threat_domains)):
            feed_matched = True
    except Exception:
        pass

    tasks = []
    hostname = parsed.hostname if parsed else None
    if features['has_https'] and hostname and not features['has_ip']:
        tasks.append(_check_ssl_certificate_async(hostname))
    tasks.append(_test_url_head_get_async(features['normalized_url']))
    tasks.append(follow_redirects_async(features['normalized_url']))

    page_signals: Optional[Dict[str, Any]] = None
    if deep:
        # Minimal deep signals to avoid heavy parsing; API may add its own
        pass

    results = await asyncio.gather(*tasks, return_exceptions=True)
    idx = 0
    if features['has_https'] and hostname and not features['has_ip']:
        ssl_res = results[idx] if not isinstance(results[idx], Exception) else None
        features['ssl_valid'] = ssl_res
        idx += 1
    rt_res = results[idx] if not isinstance(results[idx], Exception) else (0.0, 0)
    response_time, _ = rt_res if isinstance(rt_res, tuple) else (0.0, 0)
    features['response_time'] = response_time
    idx += 1
    redir_res = results[idx] if not isinstance(results[idx], Exception) else (features['normalized_url'], 0)
    _, redirect_count = redir_res if isinstance(redir_res, tuple) else (features['normalized_url'], 0)
    features['redirect_count'] = redirect_count

    score = 0.0
    reasons = []

    if feed_matched:
        score += 0.35

    if features['has_ip']:
        score += 0.4
        reasons.append("🚨 URL contains IP address instead of domain")

    if features['has_at_symbol']:
        score += 0.35
        reasons.append("🚨 Contains @ symbol (common in phishing)")

    if features.get('data_or_js_protocol'):
        score += 0.4
        reasons.append("🚨 Uses data: or javascript: scheme")

    if features['has_https'] and features['ssl_valid'] == 0:
        score += 0.3
        reasons.append("🚨 Invalid SSL certificate")

    if features.get('tld_suspicious'):
        score += 0.25
        reasons.append("⚠️ Suspicious top-level domain")

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
        score += 0.25; reasons.append("⚠️ Excessive number of subdomains")
    elif features['subdomain_count'] >= 3:
        score += 0.15; reasons.append("⚠️ High number of subdomains")

    if features['url_length'] > 150:
        score += 0.2; reasons.append("⚠️ Unusually long URL")
    elif features['url_length'] > 100:
        score += 0.1; reasons.append("⚠️ Long URL")

    if not features['has_https']:
        score += 0.25; reasons.append("⚠️ Does not use HTTPS")

    if features['has_redirect'] or features['redirect_count'] > 0:
        score += 0.2; reasons.append("⚠️ Contains redirects")

    if features['has_shortener']:
        score += 0.15; reasons.append("⚠️ Uses URL shortener")

    if features['has_hyphen']:
        score += 0.1; reasons.append("⚠️ Contains hyphens in domain")
    if features['has_underscore']:
        score += 0.1; reasons.append("⚠️ Contains underscores in domain")
    if features['has_suspicious_keywords']:
        score += 0.1; reasons.append("⚠️ Contains suspicious keywords")
    if features.get('suspicious_filename'):
        score += 0.1; reasons.append("⚠️ Suspicious filename (e.g., login.php)")

    if features['domain_length'] > 25:
        score += 0.05; reasons.append("⚠️ Very long domain name")
    elif features['domain_length'] > 20:
        score += 0.03; reasons.append("⚠️ Long domain name")

    if features['path_length'] > 80:
        score += 0.08; reasons.append("⚠️ Very long URL path")
    elif features['path_length'] > 50:
        score += 0.05; reasons.append("⚠️ Long URL path")

    if features.get('digit_ratio_domain', 0) > 0.3:
        score += 0.08; reasons.append("⚠️ Many digits in domain")
    if features.get('hyphen_count', 0) >= 3:
        score += 0.06; reasons.append("⚠️ Multiple hyphens in domain")
    if features.get('percent_encoding'):
        score += 0.05; reasons.append("⚠️ Percent-encoding present")
    if features.get('entropy_domain', 0) > 3.5:
        score += 0.08; reasons.append("⚠️ High domain randomness")
    if features.get('entropy_path', 0) > 4.0:
        score += 0.05; reasons.append("⚠️ High path randomness")

    # Domain age skipped here (requires WHOIS; handled in API variant), so no age-based score

    # Response time mild signal
    if features['response_time'] > 3:
        score += 0.05; reasons.append("⚠️ Slow response time")

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

    return {
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
        'redirect_count': features['redirect_count'],
        'analysis_timestamp': datetime.now().isoformat(),
        'deep': bool(deep),
        'page': page_signals or {},
        'feed_matched': feed_matched,
    }


