from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
from app.agent import ITDRAgent
from app.models import AlertInput, IncidentResponse

app = FastAPI(
    title="ITDR Agent — Identity Threat Detection & Response",
    description="Agentic AI system for detecting and responding to identity-based threats using Anthropic Claude API, SailPoint, and Microsoft Sentinel",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

agent = ITDRAgent()

@app.get("/")
def root():
    return {
        "name": "ITDR Agent",
        "status": "running",
        "description": "Identity Threat Detection & Response powered by Agentic AI"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/api/analyze-alert", response_model=IncidentResponse)
async def analyze_alert(alert: AlertInput):
    """
    Analyze a Sentinel security alert using AI agent.
    Correlates with SailPoint identity data and returns risk assessment + recommended actions.
    """
    try:
        result = await agent.analyze(alert)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts/mock")
def get_mock_alerts():
    """Returns sample Sentinel alerts for testing"""
    import json, os
    with open("data/sentinel_alerts.json") as f:
        return json.load(f)

@app.get("/api/identities/mock")
def get_mock_identities():
    """Returns sample SailPoint identity data for testing"""
    import json
    with open("data/sailpoint_identities.json") as f:
        return json.load(f)

@app.get("/api/incidents")
def get_incidents():
    """Returns all generated incidents"""
    import json, os
    if not os.path.exists("data/incidents.json"):
        return []
    with open("data/incidents.json") as f:
        return json.load(f)

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
