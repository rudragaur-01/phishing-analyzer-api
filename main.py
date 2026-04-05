# -------------------------------
# Run instructions:
# pip install -r requirements.txt
# uvicorn main:app --reload
# Access Swagger UI: http://127.0.0.1:8000/docs
# -------------------------------

# Phishing Analyzer API | Python, FastAPI, WHOIS, Threat Intelligence
# - Developed a Python-based API to detect phishing URLs using URL heuristics and domain intelligence.
# - Implemented an automated scoring system to classify URLs as Phishing, Suspicious, or Legitimate.
# - Integrated checks for URL length, IP-based URLs, suspicious keywords, and domain age.
# - Enabled automated threat assessment for potential phishing attacks, improving early detection capabilities.


from fastapi import FastAPI
from models import URLRequest, URLResponse
from utils.url_analysis import analyze_url_features
from utils.domain_info import extract_domain, get_domain_age
from utils.verdict import get_verdict
import logging

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

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
    if age is not None and age < 30:
        score += 30
        reasons.append("Domain is very new (<30 days)")

    # Determine verdict
    verdict = get_verdict(score)

    # Simulated SOC alert (console)
    if verdict in ["Phishing", "Suspicious"]:
        alert_message = (
            f"ALERT: {verdict} URL detected!\n"
            f"  URL     : {url}\n"
            f"  Domain  : {domain}\n"
            f"  Score   : {score}\n"
            f"  Reasons : {', '.join(reasons)}\n"
            f"  Action  : Escalate or Monitor"
        )
        logger.warning(alert_message)

    # Return API response
    return URLResponse(
        url=url,
        domain=domain,
        domain_age_days=age,
        risk_score=score,
        verdict=verdict,
        reasons=reasons
    )