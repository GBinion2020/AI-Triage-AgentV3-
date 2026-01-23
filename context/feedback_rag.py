from typing import List, Dict, Any, Optional, Tuple
import os
import sys
import sqlite3
from pathlib import Path

# Ensure we can import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None

class FeedbackRAG:
    def __init__(self):
        """Initialize Feedback RAG using Postgres feedback store."""
        self.db_type, self.db_target = self._get_db_config()

    def _get_db_config(self) -> Tuple[str, str]:
        db_url = os.getenv("FEEDBACK_DB_URL")
        if db_url:
            if db_url.startswith("sqlite:///"):
                return ("sqlite", db_url.replace("sqlite:///", "", 1))
            if db_url.startswith("sqlite://"):
                return ("sqlite", db_url.replace("sqlite://", "", 1))
            return ("postgres", db_url)

        db_path = os.getenv("FEEDBACK_DB_PATH")
        if db_path:
            return ("sqlite", db_path)

        default_path = Path(__file__).resolve().parents[1] / "feedback_api" / "feedback.db"
        return ("sqlite", str(default_path))

    def _query_feedback_postgres(self, patterns: List[str], n_results: int) -> List[Dict[str, Any]]:
        if psycopg is None:
            return []
        placeholders = " OR ".join(
            ["description ILIKE %s", "issue_summary ILIKE %s", "close_note ILIKE %s"] * len(patterns)
        )
        params: List[Any] = []
        for pat in patterns:
            params.extend([pat, pat, pat])
        sql = f"""
            SELECT
                issue_key,
                issue_summary,
                issue_status,
                jira_updated_ms,
                detection_classification,
                triage_verdict,
                close_note
            FROM jira_feedback
            WHERE {placeholders}
            ORDER BY jira_updated_ms DESC
            LIMIT %s;
        """
        params.append(n_results)
        with psycopg.connect(self.db_target) as conn:
            rows = conn.execute(sql, params).fetchall()
        return self._format_rows(rows)

    def _query_feedback_sqlite(self, patterns: List[str], n_results: int) -> List[Dict[str, Any]]:
        db_path = Path(self.db_target)
        if not db_path.exists():
            return []
        placeholders = " OR ".join(
            ["lower(description) LIKE ?", "lower(issue_summary) LIKE ?", "lower(close_note) LIKE ?"] * len(patterns)
        )
        params: List[Any] = []
        for pat in patterns:
            lowered = pat.lower()
            params.extend([lowered, lowered, lowered])
        sql = f"""
            SELECT
                issue_key,
                issue_summary,
                issue_status,
                jira_updated_ms,
                detection_classification,
                triage_verdict,
                close_note
            FROM jira_feedback
            WHERE {placeholders}
            ORDER BY jira_updated_ms DESC
            LIMIT ?;
        """
        params.append(n_results)
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
        return self._format_rows(rows)

    def _format_rows(self, rows: List[tuple]) -> List[Dict[str, Any]]:
        results = []
        for row in rows:
            results.append(
                {
                    "issue_key": row[0],
                    "issue_summary": row[1],
                    "issue_status": row[2],
                    "jira_updated_ms": row[3],
                    "detection_classification": row[4],
                    "triage_verdict": row[5],
                    "close_note": row[6],
                }
            )
        return results

    def _query_feedback(self, patterns: List[str], n_results: int) -> List[Dict[str, Any]]:
        if not patterns:
            return []
        if self.db_type == "postgres":
            if not self.db_target:
                return []
            return self._query_feedback_postgres(patterns, n_results)
        return self._query_feedback_sqlite(patterns, n_results)

    def get_related_lessons(
        self,
        query: str,
        n_results: int = 2,
        host: Optional[str] = None,
        user: Optional[str] = None,
    ) -> str:
        """
        Retrieves related analyst feedback from the database.
        
        Args:
            query: The alert name or description to search for.
            n_results: Max number of lessons to retrieve.
            
        Returns:
            A formatted string of lessons learned, or an empty note if none found.
        """
        try:
            patterns = []
            if query:
                patterns.append(f"%{query}%")
            if host:
                patterns.append(f"%{host}%")
            if user:
                patterns.append(f"%{user}%")

            results = self._query_feedback(patterns, n_results)
            
            if not results:
                return "No matching past investigations found in the feedback loop database."
                
            formatted_results = []
            for r in results:
                entry = (
                    f"--- PAST INCIDENT ({r['issue_key']}) ---\n"
                    f"VERDICT: {r['triage_verdict']} ({r['detection_classification']})\n"
                    f"NOTES: {r['close_note']}\n"
                )
                formatted_results.append(entry)
                
            return "\n".join(formatted_results)
            
        except Exception as e:
            # "Ignore if error" - Log it but don't break the investigation
            print(f"Feedback RAG Error (Non-Critical): {str(e)}")
            return "Feedback database is currently unavailable or empty. Proceed with standard triage."
