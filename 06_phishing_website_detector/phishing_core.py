import re
import socket
from urllib.parse import urlparse

# ---------------- Reference data ----------------

# Small curated sample blacklist — in production this would be a live feed
# (PhishTank, Google Safe Browsing, etc.). Demonstrates the concept locally.
BLACKLISTED_DOMAINS = {
    "secure-paypal-verify.com",
    "login-appleid-support.com",
    "amazon-account-update.net",
    "verify-microsoft-billing.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "shorte.st", "adf.ly"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".click", ".gq", ".tk",
    ".ml", ".cf", ".work", ".support", ".info", ".loan"
}

SUSPICIOUS_KEYWORDS = {
    "verify", "secure", "update", "confirm", "signin", "login",
    "account", "banking", "suspend", "unlock", "webscr"
}

# A handful of frequently-impersonated brands for lookalike-domain detection
PROTECTED_BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "netflix", "instagram", "bankofamerica", "chase"
}

CHAR_SUBSTITUTIONS = [
    ("0", "o"), ("1", "l"), ("1", "i"), ("rn", "m"), ("vv", "w"), ("5", "s")
]


# ---------------- Helpers ----------------

def levenshtein(a, b):
    """Standard edit-distance calculation — used to catch near-miss brand lookalikes."""
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def get_registrable_part(hostname):
    """Best-effort second-level domain extraction, e.g. 'accounts.paypa1.com' -> 'paypa1'."""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return hostname


def is_ip_address(host):
    try:
        socket.inet_aton(host)
        return True
    except (OSError, TypeError):
        return False


# ---------------- Rule checks ----------------
# Each rule returns (triggered: bool, weight: int, message: str)

def rule_blacklist(hostname, url):
    if hostname in BLACKLISTED_DOMAINS:
        return True, 100, f"'{hostname}' matches a known phishing blacklist entry"
    return False, 0, ""


def rule_ip_host(hostname):
    if is_ip_address(hostname):
        return True, 30, "URL uses a raw IP address instead of a domain name"
    return False, 0, ""


def rule_at_symbol(url):
    if "@" in url.split("://")[-1]:
        return True, 20, "URL contains '@', which browsers use to mask the real destination"
    return False, 0, ""


def rule_excessive_subdomains(hostname):
    dot_count = hostname.count(".")
    if dot_count >= 4:
        return True, 15, f"Unusually high number of subdomains ({dot_count} dots)"
    return False, 0, ""


def rule_url_length(url):
    if len(url) > 90:
        return True, 10, f"URL is unusually long ({len(url)} characters) — often used to obscure the real link"
    return False, 0, ""


def rule_shortener(hostname):
    if hostname in URL_SHORTENERS:
        return True, 25, f"'{hostname}' is a URL shortener — hides the real destination"
    return False, 0, ""


def rule_suspicious_tld(hostname):
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return True, 15, f"Domain uses a TLD ({tld}) disproportionately associated with phishing"
    return False, 0, ""


def rule_suspicious_keywords(url):
    lowered = url.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    if hits:
        return True, 10, f"Contains suspicious keyword(s): {', '.join(hits[:3])}"
    return False, 0, ""


def rule_no_https(scheme):
    if scheme != "https":
        return True, 5, "Connection is not secured with HTTPS"
    return False, 0, ""


def rule_brand_lookalike(hostname):
    registrable = get_registrable_part(hostname).lower()

    if registrable in PROTECTED_BRANDS:
        return False, 0, ""  # exact match to a real brand name is fine

    # 1. Brand name embedded inside a longer label — the single most common
    #    real-world phishing pattern (e.g. "paypal-account-update", "amazon-secure-login")
    for brand in PROTECTED_BRANDS:
        if brand in registrable:
            return True, 25, (
                f"Domain label '{registrable}' contains the brand name '{brand}' "
                f"but is not the official '{brand}.com' — a common phishing naming pattern"
            )

    # 2. Homograph / character-substitution check across the whole label
    #    (e.g. 'rnicrosoft-support' -> 'microsoft-support')
    normalized = registrable
    for old, new in CHAR_SUBSTITUTIONS:
        normalized = normalized.replace(old, new)
    if normalized != registrable:
        for brand in PROTECTED_BRANDS:
            if brand in normalized:
                return True, 30, f"'{registrable}' uses character substitution to imitate '{brand}'"

    # 3. Typosquatting via edit distance — only compared at similar length,
    #    to catch things like 'paypa1' or 'go0gle' without false-matching unrelated short words
    for brand in PROTECTED_BRANDS:
        if abs(len(registrable) - len(brand)) <= 2:
            distance = levenshtein(registrable, brand)
            if 0 < distance <= 2:
                return True, 30, f"'{registrable}' closely resembles the brand '{brand}' (possible typosquatting)"

    return False, 0, ""


# ---------------- Optional WHOIS enrichment (fails gracefully) ----------------

def check_domain_age(hostname, timeout_seconds=4):
    """
    Returns (age_days_or_None, note_string).
    Never raises — any failure (no internet, library missing, lookup timeout,
    unsupported TLD) results in a graceful 'unavailable' note instead of crashing.
    """
    try:
        import whois  # python-whois package
    except ImportError:
        return None, "Domain age check unavailable (python-whois not installed)"

    import concurrent.futures

    def _lookup():
        return whois.whois(hostname)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_lookup)
            result = future.result(timeout=timeout_seconds)
    except Exception:
        return None, "Domain age check unavailable (lookup failed or timed out)"

    creation_date = getattr(result, "creation_date", None)
    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None

    if not creation_date:
        return None, "Domain age check unavailable (no registration data found)"

    from datetime import datetime
    age_days = (datetime.now() - creation_date).days
    return age_days, f"Domain registered {age_days} days ago"


# ---------------- Main analysis ----------------

def analyze_url(raw_url, include_domain_age=False):
    raw_url = raw_url.strip()
    if not raw_url:
        return {"error": "Empty URL"}

    if not re.match(r'^https?://', raw_url, re.IGNORECASE):
        raw_url = "http://" + raw_url  # allow input without scheme

    parsed = urlparse(raw_url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return {"error": "Could not parse a valid hostname from this URL"}

    if not re.match(r'^[a-z0-9.\-]+$', hostname):
        return {"error": "This does not look like a valid URL"}

    checks = [
        rule_blacklist(hostname, raw_url),
        rule_ip_host(hostname),
        rule_brand_lookalike(hostname),
        rule_shortener(hostname),
        rule_at_symbol(raw_url),
        rule_excessive_subdomains(hostname),
        rule_suspicious_tld(hostname),
        rule_url_length(raw_url),
        rule_suspicious_keywords(raw_url),
        rule_no_https(parsed.scheme),
    ]

    triggered = [(w, m) for hit, w, m in checks if hit]
    score = min(100, sum(w for w, m in triggered))
    reasons = [m for w, m in sorted(triggered, key=lambda x: -x[0])]

    domain_age_note = None
    if include_domain_age:
        age_days, note = check_domain_age(hostname)
        domain_age_note = note
        if age_days is not None and age_days < 180:
            score = min(100, score + 15)
            reasons.insert(0, f"Newly registered domain ({age_days} days old) — common in phishing campaigns")

    if score >= 55:
        verdict, color = "Dangerous", "#c0392b"
    elif score >= 25:
        verdict, color = "Suspicious", "#f39c12"
    else:
        verdict, color = "Safe", "#27ae60"

    return {
        "url": raw_url,
        "hostname": hostname,
        "score": score,
        "verdict": verdict,
        "color": color,
        "reasons": reasons if reasons else ["No red flags detected"],
        "domain_age_note": domain_age_note,
    }