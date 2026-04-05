def get_verdict(score: int) -> str:
    if score >= 70:
        return "Phishing"
    elif score >= 40:
        return "Suspicious"
    else:
        return "Legitimate"