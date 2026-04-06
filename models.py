from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class URLRequest(BaseModel):
    url: str

class URLResponse(BaseModel):
    url: str
    domain: str
    domain_age_days: Optional[int]
    is_new_domain: Optional[bool] = False
    risk_score: int
    verdict: str
    reasons: List[str]
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_timeout: int = 0
    analysis_time: datetime = datetime.utcnow()