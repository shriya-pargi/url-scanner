import requests
import requests
from datetime import datetime
from threading import Lock, Event
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import time
from config import *
from heuristic_func import *


def scan_url(url, vt_api_key, heuristics_sensitivity=1, timeout=5):
    status = None
    try:
        response = requests.get(url, timeout=timeout)
        status = response.status_code
    except Exception:
        status = 'Unreachable'

    score = 0
    reasons = []

    if is_ip_in_url(url):
        score += 1
        reasons.append("URL contains IP address")

    if has_suspicious_words(url, heuristics_sensitivity):
        score += 1
        reasons.append("URL contains suspicious words")

    if has_phishing_keywords(url, heuristics_sensitivity):
        score += 1
        reasons.append("URL contains phishing keywords")

    if has_suspicious_tld(url):
        score += 1
        reasons.append("URL has suspicious TLD")

    if is_url_too_long(url):
        score += 1
        reasons.append("URL length is unusually long")

    domain = get_domain_from_url(url)
    domain_age = -1
    if domain:
        domain_age = get_domain_age_days(domain)
        if domain_age == -1:
            pass
        elif 0 <= domain_age < 180:
            score += 1
            reasons.append(f"Domain is very new ({domain_age} days old)")

    vt_malicious = 0
    with cache_lock:
        vt_data = vt_cache.get(url)
    if not vt_data:
        try:
            headers = {"x-apikey": vt_api_key}
            vt_url = "https://www.virustotal.com/api/v3/urls"
            submit_resp = requests.post(vt_url, headers=headers, data={'url': url}, timeout=15)
            if submit_resp.status_code == 200:
                submit_json = submit_resp.json()
                analysis_id = submit_json.get('data', {}).get('id')
                if analysis_id:
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    for _ in range(10):
                        analysis_resp = requests.get(analysis_url, headers=headers, timeout=15)
                        if analysis_resp.status_code == 200:
                            analysis_data = analysis_resp.json()
                            if 'data' in analysis_data and 'attributes' in analysis_data['data']:
                                status_ = analysis_data['data']['attributes'].get('status')
                                if status_ == 'completed':
                                    break
                        time.sleep(3)
                    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                    vt_report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                    vt_response = requests.get(vt_report_url, headers=headers, timeout=15)
                    if vt_response.status_code == 200:
                        vt_data = vt_response.json()
                        with cache_lock:
                            vt_cache[url] = vt_data
        except Exception:
            vt_data = None

    if vt_data:
        try:
            stats = vt_data['data']['attributes']['last_analysis_stats']
            vt_malicious = stats.get('malicious', 0)
            if vt_malicious > 0:
                score += vt_malicious
                reasons.append(f"VirusTotal flagged malicious ({vt_malicious} detections)")
        except Exception:
            vt_malicious = 0

    nvd_cve_count = 0
    nvd_cve_details = []
    if domain:
        nvd_keyword = get_nvd_keyword(domain)
        with cache_lock:
            nvd_data = nvd_cache.get(nvd_keyword)
        if not nvd_data:
            try:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={nvd_keyword}&resultsPerPage=10"
                resp = requests.get(nvd_url, timeout=15)
                if resp.status_code == 200:
                    nvd_data = resp.json()
                    with cache_lock:
                        nvd_cache[nvd_keyword] = nvd_data
            except Exception:
                nvd_data = None
        if nvd_data:
            try:
                nvd_cve_count = len(nvd_data.get('vulnerabilities', []))
                if nvd_cve_count > 0:
                    nvd_cve_details = extract_cve_details(nvd_data, max_cves=5)
                    score += nvd_cve_count
                    reasons.append(f"NVD reported {nvd_cve_count} CVEs: {', '.join(nvd_cve_details)}")
            except Exception:
                nvd_cve_count = 0

    ml_score = simple_ml_phishing_score(url)
    if ml_score > 0:
        score += ml_score
        reasons.append(f"Phishing keywords score: {ml_score}")

    trusted_domains = {
        "youtube.com", "google.com", "facebook.com", "twitter.com", "github.com", "wikipedia.org",
        "linkedin.com", "instagram.com", "microsoft.com", "apple.com", "amazon.com", "example.com"
    }
    if domain and any(td in domain for td in trusted_domains):
        score = 0
        reasons = ["Trusted major domain"]

    if score >= 5:
        safety = "Very Unsafe"
    elif score >= 3:
        safety = "Unsafe"
    elif score >= 2:
        safety = "Suspicious"
    else:
        safety = "Safe"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    result = {
        "url": url,
        "status": status,
        "score": score,
        "safety": safety,
        "reasons": "; ".join(reasons) if reasons else "None",
        "vt_malicious": vt_malicious,
        "nvd_cve": nvd_cve_count,
        "nvd_cve_details": nvd_cve_details,
        "timestamp": timestamp,
    }
    return result