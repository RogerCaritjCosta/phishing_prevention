import re
from urllib.parse import urlparse
from Levenshtein import distance as levenshtein_distance
import tldextract


def extract_urls(text: str) -> list[str]:
    """Extract URLs from plain text."""
    pattern = r'https?://[^\s<>"\')\]}>]+'
    return re.findall(pattern, text)


def is_ip_url(url: str) -> bool:
    """Check if URL uses an IP address instead of a domain."""
    hostname = urlparse(url).hostname or ""
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(ip_pattern, hostname))


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "j.mp", "dlvr.it", "rb.gy", "cutt.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "soo.gd", "s2r.co",
}


def is_shortened_url(url: str) -> bool:
    """Check if URL uses a known shortener service."""
    hostname = (urlparse(url).hostname or "").lower()
    return hostname in URL_SHORTENERS


BRAND_DOMAINS = [
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "wellsfargo.com", "chase.com", "citibank.com", "hsbc.com",
    "santander.com", "bbva.com", "caixabank.es", "bancsabadell.com",
    "ing.com", "openbank.es", "bankofamerica.com",
]


def check_typosquatting(url: str, threshold: int = 2) -> str | None:
    """Check if the domain is a typosquat of a known brand. Returns the brand domain if match found."""
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}".lower()

    if domain in BRAND_DOMAINS or domain in URL_SHORTENERS:
        return None

    for brand in BRAND_DOMAINS:
        brand_name = tldextract.extract(brand).domain
        if levenshtein_distance(extracted.domain, brand_name) <= threshold and extracted.domain != brand_name:
            return brand

    return None
