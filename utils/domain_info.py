import tldextract
import whois
from datetime import datetime

def extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def get_domain_age(domain: str) -> int | None:
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days
        return age_days
    except:
        return None