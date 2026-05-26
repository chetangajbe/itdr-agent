import json
import uuid
from datetime import datetime
import os

class SentinelClient:
    """
    Microsoft Sentinel Client
    In production: connects to Azure Sentinel REST API using Azure credentials
    For demo: uses mock alert data and simulates ticket creation
    """

    def __init__(self):
        self.workspace_id = os.getenv("SENTINEL_WORKSPACE_ID", "mock-workspace-id")
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "mock-subscription-id")
        self.resource_group = os.getenv("AZURE_RESOURCE_GROUP", "mock-rg")

    def get_alerts(self, limit: int = 10) -> list:
        """
        Fetch recent alerts from Microsoft Sentinel.
        Production: GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alerts
        """
        try:
            with open("data/sentinel_alerts.json") as f:
                alerts = json.load(f)
                return alerts[:limit]
        except FileNotFoundError:
            return []

    def create_ticket(self, ticket_data: dict) -> dict:
        """
        Create ServiceNow incident ticket (via Sentinel playbook or direct API).
        Production: POST to ServiceNow /api/now/table/incident
        """
        priority_map = {"P1": "1", "P2": "2", "P3": "3", "P4": "4"}
        ticket_id = f"INC{uuid.uuid4().int % 10000000:07d}"

        return {
            "ticket_id": ticket_id,
            "status": "created",
            "title": ticket_data.get("title"),
            "description": ticket_data.get("description"),
            "priority": ticket_data.get("priority"),
            "assigned_team": ticket_data.get("assigned_team"),
            "affected_user": ticket_data.get("user_id"),
            "created_at": datetime.utcnow().isoformat(),
            "url": f"https://your-instance.service-now.com/incident/{ticket_id}",
            "sla_breach_time": "4 hours" if ticket_data.get("priority") in ["P1", "P2"] else "24 hours"
        }

    def run_kql_query(self, query: str) -> list:
        """
        Run KQL query against Sentinel workspace.
        Production: POST /workspaces/{id}/query with KQL
        Example KQL: SecurityAlert | where UserPrincipalName == 'user@company.com' | take 10
        """
        # Mock response
        return [
            {
                "TimeGenerated": "2026-05-26T09:00:00Z",
                "AlertName": "Suspicious Sign-in Activity",
                "Severity": "High",
                "UserPrincipalName": "user@company.com",
                "IPAddress": "185.220.101.45",
                "Country": "Russia"
            }
        ]

    def get_alert_details(self, alert_id: str) -> dict:
        """
        Get full alert details from Sentinel.
        Production: GET /providers/Microsoft.SecurityInsights/alerts/{alertId}
        """
        alerts = self.get_alerts(50)
        for alert in alerts:
            if alert.get("alert_id") == alert_id:
                return alert
        return {"error": f"Alert {alert_id} not found"}
