from pydantic import BaseModel

class URLRequest(BaseModel):
    url: str

class URLResponse(BaseModel):
    url: str
    domain: str
    domain_age_days: int | None
    risk_score: int
    verdict: str
    reasons: list[str]