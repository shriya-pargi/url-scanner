import re
from datetime import datetime
import re
import whois
from datetime import datetime


def is_ip_in_url(url):
    return bool(re.search(r'https?://\d+\.\d+\.\d+\.\d+', url))

def has_suspicious_words(url, sensitivity=1):
    suspicious_words = ['login', 'secure', 'update', 'bank', 'verify', 'signin', 'signup', 'reset', 'auth']
    url_lower = url.lower()
    return sum(word in url_lower for word in suspicious_words) >= sensitivity

def has_phishing_keywords(url, sensitivity=1):
    phishing_words = [
        'free', 'bonus', 'prize', 'login', 'secure', 'account', 'update',
        'verify', 'bank', 'confirm', 'click', 'urgent', 'winner'
    ]
    url_lower = url.lower()
    return sum(word in url_lower for word in phishing_words) >= sensitivity

def has_suspicious_tld(url):
    suspicious_tlds = ['.biz', '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']
    url_lower = url.lower()
    return any(url_lower.endswith(tld) for tld in suspicious_tlds)

def is_url_too_long(url):
    return len(url) > 75

def get_domain_from_url(url):
    try:
        domain = re.findall(r'https?://(?:www\.)?([^/:]+)', url)
        return domain[0] if domain else None
    except Exception:
        return None

def get_domain_age_days(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return -1
        age = (datetime.now() - creation_date).days
        return age
    except Exception:
        return -1

def simple_ml_phishing_score(url):
    phishing_words = [
        'free', 'bonus', 'prize', 'login', 'secure', 'account', 'update',
        'verify', 'bank', 'confirm', 'click', 'urgent', 'winner'
    ]
    url_lower = url.lower()
    count = sum(url_lower.count(word) for word in phishing_words)
    return count

def extract_cve_details(nvd_data, max_cves=5):
    cve_list = []
    for item in nvd_data.get('vulnerabilities', [])[:max_cves]:
        cve_id = item.get('cve', {}).get('id', 'N/A')
        metrics = item.get('cve', {}).get('metrics', {})
        severity = 'Unknown'
        if 'cvssMetricV31' in metrics:
            severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
        elif 'cvssMetricV30' in metrics:
            severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
        elif 'cvssMetricV2' in metrics:
            severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'Unknown')
        cve_list.append(f"{cve_id} ({severity})")
    return cve_list

def get_nvd_keyword(domain):
    domain = domain.lower()
    for key in ["apache", "wordpress", "openssl", "microsoft", "drupal", "nginx", "php", "joomla", "oracle", "adobe"]:
        if key in domain:
            return key
    return domain.split(".")[0]