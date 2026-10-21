from pydantic import BaseModel,Field
from typing import List, Dict


class FlaggedPermission(BaseModel):
    permission: str
    risk_level: str
    feature_importance: float



class RiskAssessmentResponse(BaseModel):
    filename: str
    is_malware: int
    verdict: str
    confidence: float
    malware_probability: float
    threshold_used: float
    flagged_permissions: List[FlaggedPermission] = Field(
        default_factory=list, 
        description="List of requested dangerous permissions that triggered the alert"
    )