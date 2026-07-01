import urllib.parse

def extract_features(url):
    url_lower = url.lower()
    url_length = len(url)
    has_at_symbol = 1 if '@' in url else 0
    dot_count = url.count('.')
    has_redirect = 1 if url.rfind('//') > 7 else 0
    
    # Advanced Feature 1: Count Hyphens (Phishing links love hyphens)
    hyphen_count = url_lower.count('-')
    
    # Advanced Feature 2: Protocol Spoofing (Checking for 'http' or 'https' inside the domain path text)
    try:
        domain = urllib.parse.urlparse(url_lower).netloc
        is_ip = 1 if any(char.isdigit() for char in domain.replace('.', '')) and domain.count('.') >= 3 else 0
        
        # Flags things like "https-www-paypal-com"
        has_spoofed_protocol = 1 if "http" in domain or "https" in domain else 0
    except:
        is_ip = 0
        has_spoofed_protocol = 0

    return {
        'url_length': url_length,
        'has_at_symbol': has_at_symbol,
        'dot_count': dot_count,
        'has_redirect': has_redirect,
        'is_ip': is_ip,
        'hyphen_count': hyphen_count,
        'has_spoofed_protocol': has_spoofed_protocol
    }