import re

def analyze_url_features(url: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    if len(url) > 75:
        score += 20
        reasons.append("URL is unusually long")

    if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
        score += 30
        reasons.append("URL uses an IP address instead of domain")

    keywords = ["login", "verify", "secure", "bank"]
    for word in keywords:
        if word in url.lower():
            score += 10
            reasons.append(f"Contains suspicious keyword: {word}")

    return score, reasons