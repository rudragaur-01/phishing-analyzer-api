# -------------------------------
# Run instructions:
# pip install -r requirements.txt
# uvicorn main:app --reload
# Access Swagger UI: http://127.0.0.1:8000/docs
# -------------------------------

from fastapi import FastAPI
from models import URLRequest, URLResponse
from utils.url_analysis import analyze_url_features
from utils.domain_info import extract_domain, get_domain_age
from utils.verdict import get_verdict
import logging
from dotenv import load_dotenv
import os
import requests
import base64


load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"
# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def check_virustotal(url: str):
    """
    Check a URL against VirusTotal. If the URL is not in VT, submit it.
    Returns last_analysis_stats if available, or submission info if newly submitted.
    """
    if not VT_API_KEY:
        return {"malicious": 0, "info": "No API key provided"}

    headers = {"x-apikey": VT_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        # Step 1: Query existing report
        response = requests.get(f"{VT_URL}/{url_id}", headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            # Ensure consistent keys
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "timeout": stats.get("timeout", 0),
                "info": "Existing report retrieved"
            }

        elif response.status_code == 404:
            # Step 2: Submit URL if not found
            submit_response = requests.post(VT_URL, headers=headers, data={"url": url})
            if submit_response.status_code in [200, 201]:
                return {"malicious": 0, "suspicious": 0, "timeout": 0, "info": "URL submitted to VirusTotal"}
            else:
                return {"malicious": 0, "suspicious": 0, "timeout": 0, "info": f"Submission failed ({submit_response.status_code})"}

        else:
            return {"malicious": 0, "suspicious": 0, "timeout": 0, "info": f"VirusTotal error {response.status_code}"}

    except Exception as e:
        return {"malicious": 0, "suspicious": 0, "timeout": 0, "info": f"VirusTotal exception: {str(e)}"}
    
app = FastAPI(title="Phishing Analyzer API - SOC Demo")
    
@app.get("/")
def root():
    return {"message": "Phishing Analyzer API is running"}

@app.get("/home")
def home():
    return {"message": "Welcome to Home Route"}



@app.post("/analyze", response_model=URLResponse)
def analyze_url(data: URLRequest):
    url = data.url
    score, reasons = analyze_url_features(url)

    # Extract domain and domain age
    domain = extract_domain(url)
    age = get_domain_age(domain)
    if age is not None:
        if age < 30:
            score += 30
            reasons.append("Domain is very new (<30 days)")
    else:
        reasons.append("Domain age unknown")

    # VirusTotal check (must be inside function!)
    vt_result = check_virustotal(url)

    if "malicious" in vt_result and vt_result["malicious"] > 0:
        score += 50
        reasons.append(f"VirusTotal flags URL as malicious ({vt_result['malicious']} detections)")

    if "suspicious" in vt_result and vt_result["suspicious"] > 0:
        score += 25
        reasons.append(f"VirusTotal flags URL as suspicious ({vt_result['suspicious']} detections)")

    if "timeout" in vt_result and vt_result["timeout"] > 0:
        score += 5
        reasons.append(f"VirusTotal scan timed out on {vt_result['timeout']} engines")

    # Determine verdict
    verdict = get_verdict(score)
    alert_message = (
            f"ALERT: {verdict} URL detected!\n"
            f"  URL     : {url}\n"
            f"  Domain  : {domain}\n"
            f"  Score   : {score}\n"
            f"  Reasons : {', '.join(reasons)}\n"
            f"  Action  : Escalate or Monitor"
        )
    # Simulated SOC alert (console)
    if verdict in ["Phishing", "Suspicious"]:
        logger.warning(alert_message)
    else:
        logger.info(f"Legitimate URL checked: {url} | Score: {score}")

    # Return API response
    return URLResponse(
        url=url,
        domain=domain,
        domain_age_days=age,
        is_new_domain=(age is not None and age < 30),
        risk_score=score,
        verdict=verdict,
        reasons=reasons,
        vt_malicious=vt_result.get("malicious", 0),
        vt_suspicious=vt_result.get("suspicious", 0),
        vt_timeout=vt_result.get("timeout", 0)
    )

    