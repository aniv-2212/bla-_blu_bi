import re
from math import log2
from collections import Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import socket
import ssl
import whois
import dns.resolver
from datetime import datetime

# Note: You will need to install tldextract via: pip install tldextract
import tldextract

app = FastAPI()

# CRITICAL: Allows your local HTML page to securely talk to this Python server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- PLACEHOLDERS FOR YOUR ML MODEL PRESETS ---
# Replace or populate these arrays with your actual project requirements
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "bank", "update", "free", "wp", "admin"]
BRANDS = ["google", "microsoft", "paypal", "amazon", "netflix", "apple", "facebook"]
SHORTENERS = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "buff.ly"]
SUSPICIOUS_TLDS = ["xyz", "top", "work", "gq", "fit", "tk", "cn", "ga", "cf"]

def entropy(url: str) -> float:
    """Calculates the Shannon Entropy of a string to measure randomness."""
    if not url:
        return 0.0
    counts = Counter(url)
    length = len(url)
    return -sum((count / length) * log2(count / length) for count in counts.values())

def extract_features(url: str) -> dict:
    """Your exact feature extraction function passing all 33 features."""
    features = {}

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    hostname = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Basic Length Features
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["fragment_length"] = len(fragment)

    # Character Counts
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["underscore_count"] = url.count("_")
    features["slash_count"] = url.count("/")
    features["digit_count"] = sum(c.isdigit() for c in url)
    features["letter_count"] = sum(c.isalpha() for c in url)

    special_chars = re.findall(r'[^a-zA-Z0-9]', url)
    features["special_char_count"] = len(special_chars)

    # Protocol Features
    features["https"] = 1 if parsed.scheme == "https" else 0
    features["http"] = 1 if parsed.scheme == "http" else 0

    # IP Address Detection
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features["ip_address"] = 1 if re.search(ip_pattern, hostname) else 0

    # Domain Information
    features["domain_length"] = len(ext.domain)
    features["subdomain_count"] = len(ext.subdomain.split(".")) if ext.subdomain else 0
    features["tld_length"] = len(ext.suffix)

    # Entropy
    features["entropy"] = entropy(url)

    # Token Features
    tokens = re.split(r"[./?=&_-]", url)
    tokens = [t for t in tokens if t]
    features["token_count"] = len(tokens)

    if len(tokens):
        lengths = [len(t) for t in tokens]
        features["avg_token_length"] = sum(lengths) / len(lengths)
        features["max_token_length"] = max(lengths)
    else:
        features["avg_token_length"] = 0
        features["max_token_length"] = 0

    # Suspicious Keywords
    url_lower = url.lower()
    features["suspicious_keyword_count"] = sum(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS)
    features["brand_keyword_count"] = sum(brand in url_lower for brand in BRANDS)

    # URL Shortener & TLDs
    features["url_shortener"] = int(any(short in hostname.lower() for short in SHORTENERS))
    features["suspicious_tld"] = int(ext.suffix.lower() in SUSPICIOUS_TLDS)

    # Engineered Ratios & Extra Rules
    features["digit_ratio"] = features["digit_count"] / features["url_length"] if features["url_length"] > 0 else 0
    features["letter_ratio"] = features["letter_count"] / features["url_length"] if features["url_length"] > 0 else 0
    features["uppercase_count"] = sum(c.isupper() for c in url)

    digit_groups = re.findall(r"\d+", url)
    features["max_consecutive_digits"] = max([len(x) for x in digit_groups], default=0)

    special_groups = re.findall(r"[^a-zA-Z0-9]{2,}", url)
    features["consecutive_special_groups"] = len(special_groups)

    features["double_slash_count"] = url.count("//")
    features["has_at_symbol"] = int("@" in url)
    features["equal_count"] = url.count("=")
    features["question_count"] = url.count("?")
    features["ampersand_count"] = url.count("&")
    features["percent_count"] = url.count("%")
    features["longest_token"] = max([len(token) for token in tokens], default=0)

    features["empty_tokens"] = len([token for token in re.split(r"[./?=&_-]", url) if token == ""])

    try:
        features["has_port"] = int(parsed.port is not None)
    except Exception:
        features["has_port"] = 0

    features["domain_has_digits"] = int(any(char.isdigit() for char in ext.domain))

    return features

# Request schema definition
# Request schema definition
class URLRequest(BaseModel):
    url: str


# -----------------------------
# URL ML Analysis Endpoint
# -----------------------------
@app.post("/analyze")
async def analyze_url(data: URLRequest):

    url = data.url

    # Extract Features
    extracted_features = extract_features(url)

    # -----------------------------
    # Replace this with your ML model
    # -----------------------------
    risk_percentage = 42.0

    if (
        extracted_features["suspicious_keyword_count"] > 0
        or extracted_features["http"] == 1
    ):
        risk_percentage = 78.5

    elif (
        extracted_features["url_length"] < 30
        and extracted_features["https"] == 1
    ):
        risk_percentage = 12.0

    # Verdict
    if risk_percentage >= 75:
        verdict = "Malicious Threat Flagged"
        status_class = "danger"

    elif risk_percentage >= 40:
        verdict = "Suspicious Metrics Found"
        status_class = "warning"

    else:
        verdict = "Verified Clean URL"
        status_class = "safe"

    return {
        "url": url,
        "risk_percentage": risk_percentage,
        "verdict": verdict,
        "status_class": status_class,
        "extracted_features": extracted_features
    }


# -----------------------------
# Domain Intelligence Function
# -----------------------------
def get_domain_intelligence(url: str):

    parsed = urlparse(url)

    domain = parsed.netloc if parsed.netloc else parsed.path
    domain = domain.replace("www.", "")

    response = {
        "whoisStatus": "Unavailable",
        "age": "Unknown",
        "registrar": "Unknown",
        "expirationDate": "Unknown",
        "dnsRecordCount": 0,
        "ipAddress": "Unknown",
        "sslValid": False
    }

    # -----------------------------
    # WHOIS Lookup
    # -----------------------------
    try:

        info = whois.whois(domain)

        response["whoisStatus"] = "Available"

        if info.registrar:
            response["registrar"] = str(info.registrar)

        creation = info.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            years = (datetime.now() - creation).days // 365
            response["age"] = f"{years} Years"

        expiry = info.expiration_date

        if isinstance(expiry, list):
            expiry = expiry[0]

        if expiry:
            response["expirationDate"] = expiry.strftime("%d %b %Y")

    except Exception as e:
        print("WHOIS Error:", e)

    # -----------------------------
    # DNS Records
    # -----------------------------
    try:

        answers = dns.resolver.resolve(domain, "A")

        response["dnsRecordCount"] = len(answers)

    except Exception as e:
        print("DNS Error:", e)

    # -----------------------------
    # IP Address
    # -----------------------------
    try:

        response["ipAddress"] = socket.gethostbyname(domain)

    except Exception as e:
        print("IP Error:", e)

    # -----------------------------
    # SSL Certificate
    # -----------------------------
    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ):

                response["sslValid"] = True

    except Exception as e:

        print("SSL Error:", e)

        response["sslValid"] = False

    return response


# -----------------------------
# Domain Intelligence API
# -----------------------------
@app.get("/api/analyze-domain")
async def analyze_domain(url: str):

    return get_domain_intelligence(url)


# -----------------------------
# Run FastAPI
# -----------------------------
if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000
    )