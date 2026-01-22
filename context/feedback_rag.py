from typing import List, Dict, Any
import os
import sys

# Ensure we can import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from rag.vectordb import MITREVectorDB

class FeedbackRAG:
    def __init__(self):
        """Initialize Feedback RAG using the central VectorDB."""
        self.db = MITREVectorDB()
        
    def get_related_lessons(self, query: str, n_results: int = 2) -> str:
        """
        Retrieves related analyst feedback from the database.
        
        Args:
            query: The alert name or description to search for.
            n_results: Max number of lessons to retrieve.
            
        Returns:
            A formatted string of lessons learned, or an empty note if none found.
        """
        try:
            results = self.db.query_feedback(query, n_results=n_results)
            
            if not results:
                return "No matching past investigations found in the feedback loop database."
                
            formatted_results = []
            for r in results:
                entry = (
                    f"--- PAST INCIDENT (ID: {r['alert_id']}) ---\n"
                    f"VERDICT: {r['verdict']}\n"
                    f"ANALYST NOTES: {r['notes']}\n"
                    f"RELATED ARTIFACTS: {r['artifacts']}\n"
                )
                formatted_results.append(entry)
                
            return "\n".join(formatted_results)
            
        except Exception as e:
            # "Ignore if error" - Log it but don't break the investigation
            print(f"Feedback RAG Error (Non-Critical): {str(e)}")
            return "Feedback database is currently unavailable or empty. Proceed with standard triage."
