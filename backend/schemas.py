from pydantic import BaseModel, Field
from typing import List, Dict, Any


class FlaggedPermission(BaseModel):
    permission: str
    risk_level: str
    feature_importance: float


class RiskAssessmentResponse(BaseModel):
    filename: str
    is_malware: int = Field(
        ..., 
        description="-1: Suspicious, 0: Benign/Safe, 1: Malware"
    )
    verdict: str
    risk_tier: str
    confidence: float
    static_score: float
    ml_score: float
    total_score: float
    thresholds_used: Dict[str, float]
    audit_trail: Dict[str, Any]
    triggered_rules: List[Dict[str, Any]]