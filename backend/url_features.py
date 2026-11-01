import re
import math
import ipaddress

from urllib.parse import urlparse
from collections import Counter


# ==========================================
# CONFIGURATION
# ==========================================

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure",
    "account", "password", "update",
    "banking", "wallet", "confirm",
    "recover", "authenticate", "payment",
    "credential", "suspended", "unlock"
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "click", "work",
    "rest", "gq", "tk", "ml",
    "cf", "shop"
]

BRANDS = [
    "google", "paypal", "amazon",
    "microsoft", "facebook", "instagram",
    "netflix", "apple", "sbi",
    "coinbase", "binance"
]


# ==========================================
# ENTROPY CALCULATION
# ==========================================

def calculate_entropy(text):

    if not text:
        return 0

    counts = Counter(text)

    entropy = 0

    for count in counts.values():

        probability = count / len(text)

        entropy -= probability * math.log2(probability)

    return entropy


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def extract_features(url):

    url = str(url).strip().lower()

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""

    full_domain_parts = hostname.split(".")

    subdomain_count = max(0, len(full_domain_parts) - 2)

    tld = full_domain_parts[-1] if full_domain_parts else ""

    # IP address detection

    try:

        ipaddress.ip_address(hostname)

        has_ip = 1

    except ValueError:

        has_ip = 0

    # Suspicious words

    suspicious_word_count = sum(
        word in url for word in SUSPICIOUS_WORDS
    )

    # Suspicious TLD

    suspicious_tld = int(tld in SUSPICIOUS_TLDS)

    # Brand impersonation indicator

    brand_count = sum(
        brand in hostname for brand in BRANDS
    )

    # Encoded URL characters

    encoded_count = len(
        re.findall(r"%[0-9a-f]{2}", url)
    )

    # Digit ratio

    digit_count = sum(character.isdigit() for character in url)

    digit_ratio = digit_count / max(len(url), 1)

    # Port detection

    try:

        has_port = int(parsed.port is not None)

    except ValueError:

        has_port = 1

    # HTTPS detection

    is_https = int(parsed.scheme == "https")

    # URL features

    features = [

        # Basic URL features
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("/"),

        # Protocol and IP features
        is_https,
        has_ip,
        has_port,

        # Domain features
        len(hostname),
        len(path),
        len(query),
        subdomain_count,
        len(tld),

        # Suspicious patterns
        suspicious_word_count,
        suspicious_tld,
        brand_count,
        encoded_count,
        digit_ratio,

        # Advanced features
        calculate_entropy(url),
        calculate_entropy(hostname),
        int("xn--" in hostname),
        int("//" in urlparse(url).path),
        int(bool(re.search(r"(.)\1{4,}", hostname)))
    ]

    return features