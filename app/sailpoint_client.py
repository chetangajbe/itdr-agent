import json
import os
from typing import Optional

class SailPointClient:
    """
    SailPoint ISC/IIQ Client
    In production: connects to real SailPoint REST API
    For demo: uses mock identity data from JSON file
    """

    def __init__(self):
        self.base_url = os.getenv("SAILPOINT_BASE_URL", "https://your-tenant.api.identitynow.com")
        self.client_id = os.getenv("SAILPOINT_CLIENT_ID", "mock-client-id")
        self.client_secret = os.getenv("SAILPOINT_CLIENT_SECRET", "mock-secret")
        self._load_mock_data()

    def _load_mock_data(self):
        try:
            with open("data/sailpoint_identities.json") as f:
                identities = json.load(f)
                self.mock_identities = {i["user_id"]: i for i in identities}
        except FileNotFoundError:
            self.mock_identities = {}

    def get_identity(self, user_id: str) -> dict:
        """
        Fetch identity details from SailPoint ISC.
        Production: GET /v3/identities/{id}
        """
        if user_id in self.mock_identities:
            return self.mock_identities[user_id]

        # Default mock response for unknown users
        return {
            "user_id": user_id,
            "display_name": f"User {user_id}",
            "department": "Unknown",
            "role": "Standard User",
            "risk_score": 25.0,
            "entitlements": ["basic-access"],
            "recent_access": [],
            "is_privileged": False,
            "location": "Unknown",
            "account_status": "active",
            "last_login": "2026-05-20T09:00:00Z",
            "manager": "manager@company.com"
        }

    def suspend_account(self, user_id: str) -> dict:
        """
        Suspend user account in SailPoint ISC.
        Production: PATCH /v3/accounts/{id} with lifecycleState: SUSPENDED
        """
        return {
            "status": "success",
            "action": "account_suspended",
            "user_id": user_id,
            "message": f"Account {user_id} suspended successfully in SailPoint ISC"
        }

    def revoke_entitlements(self, user_id: str, entitlements: list) -> dict:
        """
        Revoke specific entitlements for a user via SailPoint provisioning.
        Production: POST /v3/access-requests with REVOKE_ACCESS type
        """
        return {
            "status": "success",
            "action": "entitlements_revoked",
            "user_id": user_id,
            "revoked": entitlements,
            "provisioning_task_id": f"TASK-{user_id}-001"
        }

    def trigger_certification(self, user_id: str) -> dict:
        """
        Trigger emergency access certification campaign for user.
        Production: POST /v3/certification-campaigns
        """
        return {
            "status": "success",
            "campaign_id": f"CERT-EMERGENCY-{user_id}",
            "type": "EMERGENCY_ACCESS_REVIEW",
            "user_id": user_id,
            "due_date": "2026-05-28T00:00:00Z"
        }
