"""URL / Link Checker (static analysis).

Checks a link for phishing / malware-delivery warning signs WITHOUT ever opening
it - the URL text is only parsed and scored, so it is completely safe.
"""
import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
                   "work", "rest", "country", "kim", "mov", "loan", "icu"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at"}
KEYWORDS = ["login", "verify", "update", "secure", "account", "banking", "wallet",
            "password", "signin", "confirm", "unlock", "bonus", "free", "gift", "kyc"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
          "instagram", "whatsapp", "sbi", "hdfc", "icici", "paytm", "phonepe"]
PAYLOAD_EXTS = (".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jar", ".apk",
                ".msi", ".ps1", ".zip", ".rar", ".iso", ".dll")


def check_url(raw: str):
    url = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    path = (p.path or "").lower()
    findings, score = [], 0

    def hit(points, name, detail):
        nonlocal score
        score += points
        findings.append({"name": name, "points": points, "detail": detail})

    if not host:
        return {"url": raw, "score": 0, "level": "INVALID", "findings": [],
                "verdict": "Not a valid URL"}

    try:
        ipaddress.ip_address(host)
        hit(25, "IP address instead of domain", f"Host is a raw IP ({host})")
    except ValueError:
        pass

    if p.scheme != "https":
        hit(10, "No HTTPS", "Connection would not be encrypted")
    if "@" in raw:
        hit(20, "'@' symbol in URL", "Browsers ignore everything before '@' - common trick")
    if len(raw) > 75:
        hit(10, "Very long URL", f"{len(raw)} characters (often used to hide the real domain)")
    if host.count(".") >= 3:
        hit(10, "Many subdomains", host)
    if host.count("-") >= 2:
        hit(10, "Many hyphens in domain", host)
    if "xn--" in host:
        hit(20, "Punycode domain", "May imitate a real domain with look-alike characters")

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        hit(15, "Suspicious domain ending", f".{tld} is frequently abused")
    if host in SHORTENERS:
        hit(10, "URL shortener", "Real destination is hidden")

    found_kw = [k for k in KEYWORDS if k in host or k in path]
    if found_kw:
        hit(min(20, 10 * len(found_kw)), "Phishing keywords", ", ".join(found_kw))

    registered = ".".join(host.split(".")[-2:])
    for b in BRANDS:
        if b in host and not registered.startswith(b + "."):
            hit(25, "Possible brand impersonation", f"Mentions '{b}' but real domain is {registered}")
            break

    if path.endswith(PAYLOAD_EXTS):
        hit(25, "Executable / archive download", f"Link downloads a {path.rsplit('.', 1)[-1]} file "
                                                 "- possible ransomware payload")

    score = min(score, 100)
    level = "CRITICAL" if score >= 60 else "WARNING" if score >= 30 else "SAFE"
    verdict = {"SAFE": "No obvious warning signs",
               "WARNING": "Suspicious - be careful",
               "CRITICAL": "Likely malicious / phishing link"}[level]
    return {"url": raw, "host": host, "score": score, "level": level,
            "verdict": verdict, "findings": findings}
