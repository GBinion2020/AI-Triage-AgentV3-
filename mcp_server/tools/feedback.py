from typing import List, Dict, Any, Optional
import os
import sys
import uuid

# Ensure we can import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from rag.vectordb import MITREVectorDB

def ingest_feedback(alert_id: str, analyst_notes: str, verdict: str, artifacts: Optional[List[str]] = None) -> str:
    """
    Ingests analyst feedback into the ChromaDB feedback_loop collection.
    
    Args:
        alert_id: The ID of the alert being closed.
        analyst_notes: The detailed investigation notes from the analyst.
        verdict: The final classification (e.g., True Positive, False Positive).
        artifacts: Optional list of related artifacts (IPs, Hashes, etc.).
    """
    try:
        db = MITREVectorDB()
        
        # Prepare metadata
        metadata = {
            "alert_id": alert_id,
            "verdict": verdict,
            "artifacts": str(artifacts or [])
        }
        
        # Generate a unique ID for the entry
        entry_id = f"fb_{uuid.uuid4().hex[:8]}"
        
        # Add to collection
        db.feedback_collection.add(
            ids=[entry_id],
            documents=[analyst_notes],
            metadatas=[metadata]
        )
        
        return f"Successfully ingested feedback for alert {alert_id}. Knowledge base updated."
        
    except Exception as e:
        return f"Error ingesting feedback: {str(e)}"
