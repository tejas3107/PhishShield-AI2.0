import sys
from pathlib import Path

# ==========================================
# PROJECT CONFIGURATION
# ==========================================

BACKEND_DIR = Path(__file__).resolve().parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

BASE_DIR = BACKEND_DIR.parent
FRONTEND_DIR = BASE_DIR / "frontend"

# ==========================================
# IMPORTS
# ==========================================

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel
from urllib.parse import urlparse

import re
import ipaddress
import joblib

from url_features import extract_features

from threat_intel import check_urlhaus

from database import (
    initialize_database,
    save_scan,
    get_scan_history,
    delete_scan,
    clear_scan_history
)


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app = FastAPI(
    title="PhishShield AI",
    description="Advanced AI-powered Phishing Detection Platform",
    version="6.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

initialize_database()


# ==========================================
# FRONTEND ROUTES
# ==========================================

if FRONTEND_DIR.exists():

    app.mount(
        "/static",
        StaticFiles(directory=str(FRONTEND_DIR)),
        name="static"
    )


@app.get("/app", include_in_schema=False)
@app.get("/ui", include_in_schema=False)
def serve_frontend_ui():

    index_file = FRONTEND_DIR / "index.html"

    if index_file.exists():
        return FileResponse(index_file)

    raise HTTPException(
        status_code=404,
        detail="Frontend interface not found"
    )


@app.get("/three.min.js", include_in_schema=False)
def serve_three_js():

    file = FRONTEND_DIR / "three.min.js"

    if file.exists():
        return FileResponse(file)

    raise HTTPException(status_code=404)


@app.get("/chart.umd.min.js", include_in_schema=False)
def serve_chart_js():

    file = FRONTEND_DIR / "chart.umd.min.js"

    if file.exists():
        return FileResponse(file)

    raise HTTPException(status_code=404)


@app.get("/confetti.browser.min.js", include_in_schema=False)
def serve_confetti_js():

    file = FRONTEND_DIR / "confetti.browser.min.js"

    if file.exists():
        return FileResponse(file)

    raise HTTPException(status_code=404)


# ==========================================
# LOAD MACHINE LEARNING MODEL
# ==========================================

MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"

model = None
model_load_error = None

try:

    if MODEL_PATH.exists():

        loaded_model = joblib.load(MODEL_PATH)

        if getattr(loaded_model, "n_features_in_", None) != 25:

            raise ValueError(
                "Model must be trained using exactly 25 features."
            )

        model = loaded_model

        print("PhishShield AI: 25-feature model loaded!")

    else:

        model_load_error = "Model file not found"

except Exception as error:

    model_load_error = str(error)

    print("Model loading error:", model_load_error)


# ==========================================
# REQUEST MODEL
# ==========================================

class ScanRequest(BaseModel):

    text: str

    scan_type: str = "auto"


# ==========================================
# DETECTION CONFIGURATION
# ==========================================

SUSPICIOUS_WORDS = [

    "urgent",
    "verify your account",
    "click here",
    "password",
    "bank account",
    "otp",
    "won a prize",
    "account blocked"

]

SHORTENERS = [

    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy"

]

SUSPICIOUS_TLDS = [

    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".work",
    ".gq",
    ".tk"

]

LEGITIMATE_DOMAINS = {

    "sbi": ["sbi.co.in"],
    "google": ["google.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com"],
    "facebook": ["facebook.com"]

}


# ==========================================
# URL EXTRACTION
# ==========================================

def extract_urls(text):

    pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'

    urls = re.findall(pattern, text)

    if not urls and "://" not in text:

        if "." in text and " " not in text:

            urls = [text]

    # Remove common trailing punctuation
    urls = [
        url.rstrip(".,!?;:)")
        for url in urls
    ]

    return list(dict.fromkeys(urls))


# ==========================================
# MACHINE LEARNING ANALYSIS
# ==========================================

def analyze_ml(url):

    if model is None:

        return {
            "prediction": "Unavailable",
            "probability": None
        }

    try:

        # Shared 25-feature extractor
        features = [extract_features(url)]

        prediction = int(
            model.predict(features)[0]
        )

        probabilities = model.predict_proba(features)[0]

        phishing_index = list(model.classes_).index(1)

        probability = float(
            probabilities[phishing_index]
        )

        return {

            "prediction": (
                "Phishing"
                if prediction == 1
                else "Legitimate"
            ),

            "probability": round(
                probability * 100,
                2
            )

        }

    except Exception as error:

        print("ML analysis error:", error)

        return {

            "prediction": "Error",
            "probability": None

        }


# ==========================================
# ADVANCED URL ANALYSIS
# ==========================================

def analyze_url(url):

    findings = []

    score = 0

    if not url.startswith(("http://", "https://")):

        url = "https://" + url

    parsed = urlparse(url)

    domain = parsed.hostname or ""

    if not domain:

        return {

            "url": url,

            "heuristic_score": 0,

            "findings": ["Invalid URL"],

            "ml_analysis": {
                "prediction": "Unavailable",
                "probability": None
            },

            "threat_intelligence": {
                "status": "not_checked"
            }

        }

    domain = domain.lower()

    # HTTPS CHECK
    if parsed.scheme != "https":

        score += 10

        findings.append(
            "Website does not use HTTPS"
        )

    # IP ADDRESS DETECTION
    try:

        ipaddress.ip_address(domain)

        score += 30

        findings.append(
            "URL uses an IP address instead of a domain"
        )

    except ValueError:

        pass

    # URL SHORTENER
    if domain in SHORTENERS:

        score += 25

        findings.append(
            "URL uses a shortening service"
        )

    # SUSPICIOUS TLD
    if any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):

        score += 20

        findings.append(
            "Suspicious domain extension"
        )

    # SUSPICIOUS KEYWORDS
    suspicious_patterns = [

        "login",
        "verify",
        "update",
        "secure",
        "account",
        "password",
        "banking",
        "payment"

    ]

    if any(
        word in url.lower()
        for word in suspicious_patterns
    ):

        score += 15

        findings.append(
            "Contains sensitive account-related keywords"
        )

    # BRAND IMPERSONATION
    for brand, legitimate_domains in LEGITIMATE_DOMAINS.items():

        if brand in domain:

            legitimate = any(

                domain == trusted
                or domain.endswith("." + trusted)

                for trusted in legitimate_domains

            )

            if not legitimate:

                score += 35

                findings.append(
                    f"Possible {brand.upper()} brand impersonation"
                )

            break

    # MACHINE LEARNING
    ml_result = analyze_ml(url)

    # THREAT INTELLIGENCE
    threat_result = check_urlhaus(url)

    return {

        "url": url,

        "heuristic_score": min(score, 100),

        "findings": findings,

        "ml_analysis": ml_result,

        "threat_intelligence": threat_result

    }


# ==========================================
# HOME ENDPOINT
# ==========================================

@app.get("/")
def home():

    return {

        "project": "PhishShield AI",

        "version": "6.0",

        "status": "active",

        "ml_model_status": (
            "active"
            if model is not None
            else "unavailable"
        ),

        "ml_features": (
            25
            if model is not None
            else 0
        ),

        "database": "connected",

        "ui_endpoint": "/app"

    }


# ==========================================
# MAIN PHISHING SCANNER
# ==========================================

@app.post("/scan")
def scan_message(request: ScanRequest):

    original_text = request.text

    text = original_text.lower()

    # KEYWORD DETECTION
    found_words = [

        word

        for word in SUSPICIOUS_WORDS

        if word in text

    ]

    keyword_score = min(
        len(found_words) * 15,
        60
    )

    # URL EXTRACTION
    urls = extract_urls(original_text)

    # URL ANALYSIS
    url_results = [

        analyze_url(url)

        for url in urls

    ]

    # HEURISTIC SCORE
    heuristic_score = max(

        (

            result["heuristic_score"]

            for result in url_results

        ),

        default=0

    )

    # ML SCORE
    ml_scores = [

        result["ml_analysis"]["probability"]

        for result in url_results

        if result["ml_analysis"]["probability"] is not None

    ]

    ml_score = max(
        ml_scores,
        default=None
    )

    # THREAT INTELLIGENCE
    known_malicious = any(

        result["threat_intelligence"].get("status")
        == "malicious"

        for result in url_results

    )

    # COMBINED RISK SCORE
    risk_score = max(

        keyword_score,

        heuristic_score,

        round(ml_score)
        if ml_score is not None
        else 0

    )

    if known_malicious:

        risk_score = 100

    # RISK CLASSIFICATION
    if risk_score >= 60:

        risk_level = "High"

    elif risk_score >= 25:

        risk_level = "Medium"

    else:

        risk_level = "Low"

    # SAVE SCAN
    save_scan(

        original_text,

        request.scan_type,

        risk_score,

        risk_level

    )

    # FINAL RESPONSE
    return {

        "project": "PhishShield AI",

        "risk_score": risk_score,

        "risk_level": risk_level,

        "suspicious_words": found_words,

        "url_analysis": url_results,

        "ml_model_status": (

            "active"
            if model is not None
            else "unavailable"

        ),

        "threat_intelligence_status": (

            "malicious URL detected"
            if known_malicious
            else "no known malicious URL detected"

        ),

        "database_status": "scan saved successfully",

        "message": "PhishShield AI scan completed successfully"

    }


# ==========================================
# SCAN HISTORY
# ==========================================

@app.get("/history")
def scan_history():

    history = get_scan_history()

    return {

        "total_scans": len(history),

        "history": history

    }


# ==========================================
# INDIVIDUAL SCAN DETAILS
# ==========================================

@app.get("/history/{scan_id}")
def individual_scan(scan_id: int):

    history = get_scan_history()

    for scan in history:

        if scan["id"] == scan_id:

            return scan

    raise HTTPException(

        status_code=404,

        detail="Scan record not found"

    )


# ==========================================
# DELETE INDIVIDUAL SCAN
# ==========================================

@app.delete("/history/{scan_id}")
def delete_individual_scan(scan_id: int):

    success = delete_scan(scan_id)

    if not success:

        raise HTTPException(

            status_code=404,

            detail="Scan record not found"

        )

    return {

        "status": "success",

        "message": f"Scan #{scan_id} deleted successfully"

    }


# ==========================================
# CLEAR HISTORY
# ==========================================

@app.delete("/history")
def clear_all_history():

    clear_scan_history()

    return {

        "status": "success",

        "message": "All scan records cleared successfully"

    }


# ==========================================
# SECURITY ANALYTICS
# ==========================================

@app.get("/stats")
def security_stats():

    history = get_scan_history()

    total = len(history)

    high = sum(

        1

        for scan in history

        if scan["classification"] == "High"

    )

    medium = sum(

        1

        for scan in history

        if scan["classification"] == "Medium"

    )

    low = sum(

        1

        for scan in history

        if scan["classification"] == "Low"

    )

    average_risk = (

        round(

            sum(
                scan["risk_score"]
                for scan in history
            ) / total,

            2

        )

        if total > 0

        else 0

    )

    return {

        "total_scans": total,

        "high_risk": high,

        "medium_risk": medium,

        "low_risk": low,

        "average_risk_score": average_risk,

        "security_status": (

            "Critical" if high > 0

            else "Monitoring" if medium > 0

            else "Protected"

        )

    }