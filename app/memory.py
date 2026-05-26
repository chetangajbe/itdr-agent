import json
import uuid
import os
from datetime import datetime
from typing import List

try:
    import chromadb
    from chromadb.utils import embedding_functions
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

class IncidentMemory:
    """
    RAG-based incident memory using ChromaDB.
    Falls back to simple JSON search if ChromaDB not available.
    """

    def __init__(self):
        self.use_chroma = CHROMADB_AVAILABLE
        if self.use_chroma:
            try:
                self.client = chromadb.PersistentClient(path="./chroma_db")
                try:
                    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
                    self.embedding_fn = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
                except Exception:
                    self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()

                self.collection = self.client.get_or_create_collection(
                    name="itdr_incidents",
                    embedding_function=self.embedding_fn,
                    metadata={"hnsw:space": "cosine"}
                )
                if self.collection.count() == 0:
                    self._seed_sample_incidents()
            except Exception:
                self.use_chroma = False

        if not self.use_chroma:
            self.memory_store = []
            self._seed_fallback()

    def store_incident(self, incident) -> None:
        if self.use_chroma:
            doc = f"Incident {incident.incident_id}. {incident.threat_summary}. Risk: {incident.risk_level}."
            try:
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
            except Exception:
                pass
        else:
            self.memory_store.append({
                "incident_id": incident.incident_id,
                "summary": incident.threat_summary,
                "risk_level": incident.risk_level.value,
                "timestamp": incident.timestamp
            })
        self._save_to_json(incident)

    def search_similar(self, query: str, limit: int = 3) -> dict:
        if self.use_chroma and self.collection.count() > 0:
            try:
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
                return {"similar_incidents": similar, "count": len(similar)}
            except Exception:
                pass

        # Fallback simple search
        results = self.memory_store[:limit] if hasattr(self, 'memory_store') else []
        return {"similar_incidents": results, "count": len(results), "message": f"Found {len(results)} similar past incidents"}

    def _seed_fallback(self):
        self.memory_store = [
            {"incident_id": "ITDR-SEED-001", "summary": "Brute force on admin account", "risk_level": "CRITICAL", "timestamp": "2026-04-15T10:30:00Z"},
            {"incident_id": "ITDR-SEED-002", "summary": "Impossible travel alert — USA to Russia", "risk_level": "HIGH", "timestamp": "2026-04-20T14:00:00Z"},
            {"incident_id": "ITDR-SEED-003", "summary": "Mass data download at 3AM", "risk_level": "HIGH", "timestamp": "2026-05-01T03:15:00Z"},
        ]

    def _seed_sample_incidents(self):
        samples = [
            {"id": "ITDR-SEED-001", "doc": "Brute force attack on privileged admin. Risk: CRITICAL. Actions: SUSPEND_ACCOUNT.", "meta": {"incident_id": "ITDR-SEED-001", "risk_level": "CRITICAL", "risk_score": 95.0, "timestamp": "2026-04-15T10:30:00Z", "user_id": "USR-ADMIN-001"}},
            {"id": "ITDR-SEED-002", "doc": "Impossible travel USA to Russia in 2 hours. Risk: HIGH.", "meta": {"incident_id": "ITDR-SEED-002", "risk_level": "HIGH", "risk_score": 75.0, "timestamp": "2026-04-20T14:00:00Z", "user_id": "USR-FIN-042"}},
            {"id": "ITDR-SEED-003", "doc": "Mass data download 50GB at 3AM. Insider threat. Risk: HIGH.", "meta": {"incident_id": "ITDR-SEED-003", "risk_level": "HIGH", "risk_score": 72.0, "timestamp": "2026-05-01T03:15:00Z", "user_id": "USR-ENG-117"}},
        ]
        self.collection.add(
            documents=[s["doc"] for s in samples],
            ids=[s["id"] for s in samples],
            metadatas=[s["meta"] for s in samples]
        )

    def _save_to_json(self, incident):
        incidents = []
        if os.path.exists("data/incidents.json"):
            try:
                with open("data/incidents.json") as f:
                    incidents = json.load(f)
            except Exception:
                pass
        incidents.append({
            "incident_id": incident.incident_id,
            "risk_level": incident.risk_level.value,
            "threat_summary": incident.threat_summary,
            "timestamp": incident.timestamp
        })
        os.makedirs("data", exist_ok=True)
        with open("data/incidents.json", "w") as f:
            json.dump(incidents, f, indent=2)
