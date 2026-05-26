import anthropic
import json
import uuid
import time
import os
from datetime import datetime
from typing import Any
from app.models import AlertInput, IncidentResponse, IdentityContext, RecommendedAction, RiskLevel
from app.sailpoint_client import SailPointClient
from app.sentinel_client import SentinelClient
from app.memory import IncidentMemory

class ITDRAgent:
    """
    Multi-step Agentic AI system for Identity Threat Detection & Response.
    Uses Anthropic Claude API with tool calling to:
    1. Analyze Sentinel security alerts
    2. Correlate with SailPoint identity data
    3. Assess risk using AI reasoning
    4. Generate incident tickets with recommended actions
    """

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", "your-api-key-here"))
        self.sailpoint = SailPointClient()
        self.sentinel = SentinelClient()
        self.memory = IncidentMemory()
        self.model = "claude-opus-4-5"

        # Define tools for the AI agent
        self.tools = [
            {
                "name": "get_identity_details",
                "description": "Fetch identity details from SailPoint for a given user ID. Returns user profile, entitlements, risk score, and access history.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "user_id": {
                            "type": "string",
                            "description": "The SailPoint user ID to look up"
                        }
                    },
                    "required": ["user_id"]
                }
            },
            {
                "name": "get_similar_incidents",
                "description": "Search the incident memory (RAG) for similar past security incidents to provide context for current threat analysis.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Description of the current threat to search similar incidents for"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of similar incidents to return",
                            "default": 3
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "calculate_risk_score",
                "description": "Calculate a composite risk score based on alert severity, user privilege level, entitlements, and historical patterns.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "alert_severity": {
                            "type": "string",
                            "description": "Severity of the alert: Low, Medium, High, Critical"
                        },
                        "is_privileged_user": {
                            "type": "boolean",
                            "description": "Whether the user has privileged access"
                        },
                        "anomaly_indicators": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of anomaly indicators detected"
                        },
                        "similar_incident_count": {
                            "type": "integer",
                            "description": "Number of similar past incidents found"
                        }
                    },
                    "required": ["alert_severity", "is_privileged_user", "anomaly_indicators"]
                }
            },
            {
                "name": "create_servicenow_ticket",
                "description": "Create an incident ticket in ServiceNow with the threat analysis and recommended remediation actions.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Incident title"
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed incident description with AI analysis"
                        },
                        "priority": {
                            "type": "string",
                            "description": "Ticket priority: P1, P2, P3, P4"
                        },
                        "assigned_team": {
                            "type": "string",
                            "description": "Team to assign the ticket to"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "Affected user ID"
                        }
                    },
                    "required": ["title", "description", "priority", "assigned_team", "user_id"]
                }
            }
        ]

    async def analyze(self, alert: AlertInput) -> IncidentResponse:
        start_time = time.time()
        incident_id = str(uuid.uuid4())[:8].upper()

        system_prompt = """You are an expert Identity Threat Detection & Response (ITDR) AI agent 
        working for an enterprise security operations center. 

        Your job is to:
        1. Analyze incoming Microsoft Sentinel security alerts
        2. Fetch and correlate SailPoint identity data for the affected user
        3. Search memory for similar past incidents
        4. Calculate a composite risk score
        5. Generate a detailed threat assessment with recommended actions
        6. Create a ServiceNow incident ticket

        Always use the available tools in sequence. Be thorough and think step by step.
        Provide clear reasoning for your risk assessment.
        Focus on identity-based threats: account compromise, privilege escalation, lateral movement, 
        insider threats, and anomalous access patterns."""

        user_message = f"""Analyze this Microsoft Sentinel security alert and perform a full ITDR investigation:

Alert ID: {alert.alert_id}
Title: {alert.title}
Description: {alert.description}
Severity: {alert.severity}
Affected User ID: {alert.user_id}
Source IP: {alert.source_ip or 'Unknown'}
Timestamp: {alert.timestamp}

Please:
1. Get the identity details for user {alert.user_id} from SailPoint
2. Search for similar past incidents in our memory
3. Calculate the risk score based on all findings
4. Create a ServiceNow incident ticket
5. Provide your complete threat analysis and recommended actions"""

        messages = [{"role": "user", "content": user_message}]
        
        tool_results = {}
        identity_data = None
        servicenow_ticket = None
        risk_score = 0.0
        ai_reasoning_parts = []

        # Agentic loop — agent calls tools until done
        max_iterations = 10
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                tools=self.tools,
                messages=messages
            )

            # Collect text reasoning
            for block in response.content:
                if hasattr(block, 'text') and block.text:
                    ai_reasoning_parts.append(block.text)

            # Check if done
            if response.stop_reason == "end_turn":
                break

            # Process tool calls
            if response.stop_reason == "tool_use":
                tool_calls = [b for b in response.content if b.type == "tool_use"]
                
                messages.append({"role": "assistant", "content": response.content})
                
                tool_results_content = []
                for tool_call in tool_calls:
                    result = self._execute_tool(tool_call.name, tool_call.input)
                    
                    # Store important results
                    if tool_call.name == "get_identity_details":
                        identity_data = result
                    elif tool_call.name == "create_servicenow_ticket":
                        servicenow_ticket = result
                    elif tool_call.name == "calculate_risk_score":
                        risk_score = result.get("risk_score", 50.0)

                    tool_results_content.append({
                        "type": "tool_result",
                        "tool_use_id": tool_call.id,
                        "content": json.dumps(result)
                    })

                messages.append({"role": "user", "content": tool_results_content})

        # Build response
        mttd = time.time() - start_time
        ai_reasoning = "\n\n".join(ai_reasoning_parts) if ai_reasoning_parts else "AI analysis completed."

        # Determine risk level
        if risk_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Build identity context
        if identity_data:
            identity_context = IdentityContext(
                user_id=alert.user_id,
                display_name=identity_data.get("display_name", "Unknown"),
                department=identity_data.get("department", "Unknown"),
                role=identity_data.get("role", "Unknown"),
                risk_score=identity_data.get("risk_score", 0.0),
                entitlements=identity_data.get("entitlements", []),
                recent_access=identity_data.get("recent_access", []),
                is_privileged=identity_data.get("is_privileged", False),
                location=identity_data.get("location", "Unknown")
            )
        else:
            identity_context = IdentityContext(
                user_id=alert.user_id,
                display_name="Unknown",
                department="Unknown",
                role="Unknown",
                risk_score=0.0,
                entitlements=[],
                recent_access=[],
                is_privileged=False,
                location="Unknown"
            )

        # Recommended actions based on risk
        recommended_actions = self._get_recommended_actions(risk_level, identity_context.is_privileged)

        incident = IncidentResponse(
            incident_id=f"ITDR-{incident_id}",
            alert_id=alert.alert_id,
            risk_level=risk_level,
            risk_score=risk_score,
            ai_reasoning=ai_reasoning,
            threat_summary=f"{alert.title} — {risk_level.value} risk identity threat detected for user {alert.user_id}",
            identity_context=identity_context,
            recommended_actions=recommended_actions,
            servicenow_ticket=servicenow_ticket or {"ticket_id": f"INC{uuid.uuid4().int % 1000000:07d}", "status": "created"},
            mttd_seconds=round(mttd, 2),
            timestamp=datetime.utcnow().isoformat()
        )

        # Store in memory for future RAG retrieval
        self.memory.store_incident(incident)

        return incident

    def _execute_tool(self, tool_name: str, tool_input: dict) -> dict:
        """Execute the appropriate tool based on name"""
        if tool_name == "get_identity_details":
            return self.sailpoint.get_identity(tool_input["user_id"])
        elif tool_name == "get_similar_incidents":
            return self.memory.search_similar(
                tool_input["query"],
                tool_input.get("limit", 3)
            )
        elif tool_name == "calculate_risk_score":
            return self._calculate_risk(tool_input)
        elif tool_name == "create_servicenow_ticket":
            return self.sentinel.create_ticket(tool_input)
        return {"error": f"Unknown tool: {tool_name}"}

    def _calculate_risk(self, params: dict) -> dict:
        severity_scores = {"Low": 20, "Medium": 40, "High": 70, "Critical": 90}
        base = severity_scores.get(params.get("alert_severity", "Medium"), 40)
        
        if params.get("is_privileged_user"):
            base += 20
        
        anomalies = params.get("anomaly_indicators", [])
        base += min(len(anomalies) * 5, 25)
        
        similar = params.get("similar_incident_count", 0)
        if similar > 0:
            base += min(similar * 3, 10)

        risk_score = min(base, 100)
        
        if risk_score >= 80:
            level = "CRITICAL"
        elif risk_score >= 60:
            level = "HIGH"
        elif risk_score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "breakdown": {
                "severity_base": severity_scores.get(params.get("alert_severity"), 40),
                "privilege_bonus": 20 if params.get("is_privileged_user") else 0,
                "anomaly_bonus": min(len(anomalies) * 5, 25),
                "historical_bonus": min(similar * 3, 10)
            }
        }

    def _get_recommended_actions(self, risk_level: RiskLevel, is_privileged: bool) -> list:
        actions = []
        
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            actions.append(RecommendedAction(
                action="SUSPEND_ACCOUNT",
                priority="IMMEDIATE",
                description="Immediately suspend user account in SailPoint to prevent further unauthorized access",
                automated=True
            ))
            actions.append(RecommendedAction(
                action="REVOKE_PRIVILEGED_ACCESS",
                priority="IMMEDIATE",
                description="Revoke all privileged entitlements and admin roles via SailPoint ISC",
                automated=True
            ))

        if is_privileged:
            actions.append(RecommendedAction(
                action="FORCE_MFA_RESET",
                priority="HIGH",
                description="Force MFA re-enrollment and reset all active sessions for privileged user",
                automated=False
            ))

        actions.append(RecommendedAction(
            action="FORENSIC_REVIEW",
            priority="HIGH",
            description="Conduct forensic review of user access logs in Microsoft Sentinel for past 30 days",
            automated=False
        ))
        actions.append(RecommendedAction(
            action="ACCESS_CERTIFICATION",
            priority="MEDIUM",
            description="Trigger emergency access certification campaign for affected user in SailPoint",
            automated=True
        ))
        actions.append(RecommendedAction(
            action="NOTIFY_MANAGER",
            priority="MEDIUM",
            description="Notify user's manager and HR team of security incident per policy",
            automated=False
        ))

        return actions
