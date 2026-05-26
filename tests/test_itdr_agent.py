import pytest
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.sailpoint_client import SailPointClient
from app.sentinel_client import SentinelClient
from app.models import AlertInput, RiskLevel, AlertSeverity


# ── SailPoint Client Tests ──────────────────────────────────────────────────

class TestSailPointClient:

    def setup_method(self):
        self.client = SailPointClient()

    def test_get_known_identity(self):
        identity = self.client.get_identity("USR-FIN-042")
        assert identity["user_id"] == "USR-FIN-042"
        assert identity["display_name"] == "Priya Sharma"
        assert identity["department"] == "Finance"
        assert isinstance(identity["entitlements"], list)
        assert len(identity["entitlements"]) > 0

    def test_get_privileged_identity(self):
        identity = self.client.get_identity("USR-ADMIN-007")
        assert identity["is_privileged"] == True
        assert identity["risk_score"] > 50
        assert "Domain-Admin" in identity["entitlements"]

    def test_get_unknown_identity_returns_default(self):
        identity = self.client.get_identity("USR-UNKNOWN-999")
        assert identity["user_id"] == "USR-UNKNOWN-999"
        assert identity["is_privileged"] == False
        assert identity["role"] == "Standard User"

    def test_suspend_account(self):
        result = self.client.suspend_account("USR-TEST-001")
        assert result["status"] == "success"
        assert result["action"] == "account_suspended"
        assert result["user_id"] == "USR-TEST-001"

    def test_revoke_entitlements(self):
        result = self.client.revoke_entitlements("USR-TEST-001", ["Admin-Access", "Finance-DB"])
        assert result["status"] == "success"
        assert result["action"] == "entitlements_revoked"
        assert len(result["revoked"]) == 2

    def test_trigger_certification(self):
        result = self.client.trigger_certification("USR-FIN-042")
        assert result["status"] == "success"
        assert "CERT-EMERGENCY" in result["campaign_id"]
        assert result["type"] == "EMERGENCY_ACCESS_REVIEW"

    def test_service_account_high_risk(self):
        identity = self.client.get_identity("SVC-BACKUP-001")
        assert identity["is_privileged"] == True
        assert identity["risk_score"] >= 80


# ── Sentinel Client Tests ───────────────────────────────────────────────────

class TestSentinelClient:

    def setup_method(self):
        self.client = SentinelClient()

    def test_get_alerts_returns_list(self):
        alerts = self.client.get_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) > 0

    def test_alerts_have_required_fields(self):
        alerts = self.client.get_alerts()
        required_fields = ["alert_id", "title", "description", "severity", "user_id", "timestamp"]
        for alert in alerts:
            for field in required_fields:
                assert field in alert, f"Missing field: {field}"

    def test_alert_limit(self):
        alerts = self.client.get_alerts(limit=2)
        assert len(alerts) <= 2

    def test_create_ticket_returns_ticket_id(self):
        ticket = self.client.create_ticket({
            "title": "Test Incident",
            "description": "Test description",
            "priority": "P2",
            "assigned_team": "SOC Team",
            "user_id": "USR-TEST-001"
        })
        assert "ticket_id" in ticket
        assert ticket["ticket_id"].startswith("INC")
        assert ticket["status"] == "created"

    def test_critical_alert_exists(self):
        alerts = self.client.get_alerts()
        severities = [a["severity"] for a in alerts]
        assert "Critical" in severities or "High" in severities

    def test_get_alert_by_id(self):
        alert = self.client.get_alert_details("SENT-2026-001")
        assert alert["alert_id"] == "SENT-2026-001"
        assert alert["user_id"] == "USR-FIN-042"


# ── Model Tests ─────────────────────────────────────────────────────────────

class TestModels:

    def test_alert_input_valid(self):
        alert = AlertInput(
            alert_id="TEST-001",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.HIGH,
            user_id="USR-TEST-001",
            timestamp="2026-05-26T10:00:00Z"
        )
        assert alert.alert_id == "TEST-001"
        assert alert.severity == AlertSeverity.HIGH

    def test_alert_severity_enum(self):
        assert AlertSeverity.CRITICAL == "Critical"
        assert AlertSeverity.HIGH == "High"
        assert AlertSeverity.MEDIUM == "Medium"
        assert AlertSeverity.LOW == "Low"

    def test_risk_level_enum(self):
        assert RiskLevel.CRITICAL == "CRITICAL"
        assert RiskLevel.HIGH == "HIGH"
        assert RiskLevel.MEDIUM == "MEDIUM"
        assert RiskLevel.LOW == "LOW"

    def test_optional_source_ip(self):
        alert = AlertInput(
            alert_id="TEST-002",
            title="No IP Alert",
            description="Alert without IP",
            severity=AlertSeverity.MEDIUM,
            user_id="USR-001",
            timestamp="2026-05-26T10:00:00Z"
        )
        assert alert.source_ip is None


# ── Risk Calculation Tests ──────────────────────────────────────────────────

class TestRiskCalculation:

    def setup_method(self):
        from app.agent import ITDRAgent
        self.agent = ITDRAgent()

    def test_critical_severity_high_risk(self):
        result = self.agent._calculate_risk({
            "alert_severity": "Critical",
            "is_privileged_user": True,
            "anomaly_indicators": ["impossible_travel", "after_hours", "new_location"],
            "similar_incident_count": 2
        })
        assert result["risk_score"] >= 80
        assert result["risk_level"] == "CRITICAL"

    def test_low_severity_low_risk(self):
        result = self.agent._calculate_risk({
            "alert_severity": "Low",
            "is_privileged_user": False,
            "anomaly_indicators": [],
            "similar_incident_count": 0
        })
        assert result["risk_score"] < 60

    def test_privileged_user_increases_risk(self):
        base = self.agent._calculate_risk({
            "alert_severity": "Medium",
            "is_privileged_user": False,
            "anomaly_indicators": [],
            "similar_incident_count": 0
        })
        privileged = self.agent._calculate_risk({
            "alert_severity": "Medium",
            "is_privileged_user": True,
            "anomaly_indicators": [],
            "similar_incident_count": 0
        })
        assert privileged["risk_score"] > base["risk_score"]

    def test_risk_score_max_100(self):
        result = self.agent._calculate_risk({
            "alert_severity": "Critical",
            "is_privileged_user": True,
            "anomaly_indicators": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
            "similar_incident_count": 10
        })
        assert result["risk_score"] <= 100

    def test_recommended_actions_critical(self):
        from app.models import RiskLevel
        actions = self.agent._get_recommended_actions(RiskLevel.CRITICAL, True)
        action_names = [a.action for a in actions]
        assert "SUSPEND_ACCOUNT" in action_names
        assert "REVOKE_PRIVILEGED_ACCESS" in action_names
        assert "FORENSIC_REVIEW" in action_names


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
