import chromadb
from chromadb.utils import embedding_functions
import json
import uuid
from datetime import datetime
from typing import List, Optional
import os

class IncidentMemory:
    """
    RAG-based incident memory using ChromaDB.
    Stores past ITDR incidents as vector embeddings for semantic similarity search.
    Allows the AI agent to reference historical incidents for better threat analysis.
    """

    def __init__(self):
        self.client = chromadb.PersistentClient(path="./chroma_db")
        
        # Use sentence transformers for embeddings
        try:
            self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )
        except Exception:
            # Fallback to default embeddings if sentence-transformers not available
            self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()

        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name="itdr_incidents",
            embedding_function=self.embedding_fn,
            metadata={"hnsw:space": "cosine"}
        )

        # Load sample incidents if collection is empty
        if self.collection.count() == 0:
            self._seed_sample_incidents()

    def store_incident(self, incident) -> None:
        """Store an ITDR incident in ChromaDB for future RAG retrieval"""
        doc = f"""
        Incident: {incident.incident_id}
        Threat: {incident.threat_summary}
        Risk Level: {incident.risk_level}
        Risk Score: {incident.risk_score}
        User: {incident.identity_context.user_id}
        Department: {incident.identity_context.department}
        Is Privileged: {incident.identity_context.is_privileged}
        AI Reasoning: {incident.ai_reasoning[:500] if incident.ai_reasoning else ''}
        Actions Taken: {', '.join([a.action for a in incident.recommended_actions])}
        """

        self.collection.add(
            documents=[doc],
            ids=[incident.incident_id],
            metadatas=[{
                "incident_id": incident.incident_id,
                "risk_level": incident.risk_level.value,
                "risk_score": incident.risk_score,
                "timestamp": incident.timestamp,
                "user_id": incident.identity_context.user_id
            }]
        )

        # Also save to JSON file
        self._save_to_json(incident)

    def search_similar(self, query: str, limit: int = 3) -> dict:
        """
        Semantic search for similar past incidents using vector embeddings.
        Used by AI agent to provide historical context for threat analysis.
        """
        if self.collection.count() == 0:
            return {"similar_incidents": [], "count": 0}

        results = self.collection.query(
            query_texts=[query],
            n_results=min(limit, self.collection.count()),
            include=["documents", "metadatas", "distances"]
        )

        similar = []
        for i, doc in enumerate(results["documents"][0]):
            similarity = 1 - results["distances"][0][i]
            similar.append({
                "incident_id": results["metadatas"][0][i].get("incident_id"),
                "summary": doc[:300],
                "risk_level": results["metadatas"][0][i].get("risk_level"),
                "similarity_score": round(similarity, 3),
                "timestamp": results["metadatas"][0][i].get("timestamp")
            })

        return {
            "similar_incidents": similar,
            "count": len(similar),
            "message": f"Found {len(similar)} similar past incidents"
        }

    def _seed_sample_incidents(self):
        """Seed ChromaDB with sample historical incidents for demo"""
        samples = [
            {
                "id": "ITDR-SEED-001",
                "doc": "Incident ITDR-SEED-001. Brute force attack detected on privileged admin account. User suspended immediately. Risk: CRITICAL. Actions: SUSPEND_ACCOUNT, REVOKE_PRIVILEGED_ACCESS, FORENSIC_REVIEW. Resolved in 45 minutes.",
                "meta": {"incident_id": "ITDR-SEED-001", "risk_level": "CRITICAL", "risk_score": 95.0, "timestamp": "2026-04-15T10:30:00Z", "user_id": "USR-ADMIN-001"}
            },
            {
                "id": "ITDR-SEED-002",
                "doc": "Incident ITDR-SEED-002. Impossible travel alert — user logged in from USA and Russia within 2 hours. Medium privilege user. Risk: HIGH. Actions: FORCE_MFA_RESET, FORENSIC_REVIEW, NOTIFY_MANAGER. Confirmed account compromise.",
                "meta": {"incident_id": "ITDR-SEED-002", "risk_level": "HIGH", "risk_score": 75.0, "timestamp": "2026-04-20T14:00:00Z", "user_id": "USR-FIN-042"}
            },
            {
                "id": "ITDR-SEED-003",
                "doc": "Incident ITDR-SEED-003. Mass data download detected — user downloaded 50GB from SharePoint at 3AM. Standard user. Risk: HIGH. Actions: SUSPEND_ACCOUNT, ACCESS_CERTIFICATION, FORENSIC_REVIEW. Insider threat confirmed.",
                "meta": {"incident_id": "ITDR-SEED-003", "risk_level": "HIGH", "risk_score": 72.0, "timestamp": "2026-05-01T03:15:00Z", "user_id": "USR-ENG-117"}
            },
            {
                "id": "ITDR-SEED-004",
                "doc": "Incident ITDR-SEED-004. Lateral movement detected — service account accessing multiple sensitive systems. Risk: CRITICAL. Actions: SUSPEND_ACCOUNT, REVOKE_PRIVILEGED_ACCESS. Ransomware precursor activity.",
                "meta": {"incident_id": "ITDR-SEED-004", "risk_level": "CRITICAL", "risk_score": 98.0, "timestamp": "2026-05-10T22:00:00Z", "user_id": "SVC-BACKUP-001"}
            },
            {
                "id": "ITDR-SEED-005",
                "doc": "Incident ITDR-SEED-005. Anomalous login from Tor exit node. Non-privileged user. Risk: MEDIUM. Actions: FORCE_MFA_RESET, NOTIFY_MANAGER. User confirmed it was a VPN misconfiguration.",
                "meta": {"incident_id": "ITDR-SEED-005", "risk_level": "MEDIUM", "risk_score": 45.0, "timestamp": "2026-05-15T11:00:00Z", "user_id": "USR-MKT-033"}
            }
        ]

        self.collection.add(
            documents=[s["doc"] for s in samples],
            ids=[s["id"] for s in samples],
            metadatas=[s["meta"] for s in samples]
        )

    def _save_to_json(self, incident):
        """Save incident to JSON file for API retrieval"""
        incidents = []
        if os.path.exists("data/incidents.json"):
            with open("data/incidents.json") as f:
                incidents = json.load(f)

        incidents.append({
            "incident_id": incident.incident_id,
            "alert_id": incident.alert_id,
            "risk_level": incident.risk_level.value,
            "risk_score": incident.risk_score,
            "threat_summary": incident.threat_summary,
            "user_id": incident.identity_context.user_id,
            "mttd_seconds": incident.mttd_seconds,
            "timestamp": incident.timestamp
        })

        with open("data/incidents.json", "w") as f:
            json.dump(incidents, f, indent=2)
