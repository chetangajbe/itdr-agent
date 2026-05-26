from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AlertInput(BaseModel):
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    user_id: str
    source_ip: Optional[str] = None
    timestamp: str
    raw_event: Optional[dict] = None

class IdentityContext(BaseModel):
    user_id: str
    display_name: str
    department: str
    role: str
    risk_score: float
    entitlements: List[str]
    recent_access: List[str]
    is_privileged: bool
    location: str

class RecommendedAction(BaseModel):
    action: str
    priority: str
    description: str
    automated: bool

class IncidentResponse(BaseModel):
    incident_id: str
    alert_id: str
    risk_level: RiskLevel
    risk_score: float
    ai_reasoning: str
    threat_summary: str
    identity_context: IdentityContext
    recommended_actions: List[RecommendedAction]
    servicenow_ticket: dict
    mttd_seconds: float
    timestamp: str
