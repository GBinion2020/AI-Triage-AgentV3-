from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import os
import sys
from dateutil import parser as dateutil_parser

# Ensure we can import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from elastic.client import ElasticClient

def query_host_logs(host_name: str, alert_timestamp: str, window_minutes: int = 15) -> str:
    """
    Search Elastic SIEM for logs related to a specific host around a timeframe.
    Useful for validating execution activity, logins, or abnormalities on a host.
    
    Args:
        host_name: The hostname to search for.
        alert_timestamp: The ISO timestamp of the alert (e.g. 2026-01-18T10:00:00Z).
        window_minutes: How many minutes before and after the timestamp to search (default 15).
        
    Returns:
        A string summary of the logs found.
    """
    client = ElasticClient()
    
    # Validation
    window_minutes = min(max(1, window_minutes), 120)  # Max 2 hours
    
    # Date parsing - support multiple ISO 8601 formats including timezone offsets
    try:
        # Use dateutil parser for robust ISO 8601 parsing (handles +00:00, Z, etc.)
        alert_dt = dateutil_parser.isoparse(alert_timestamp)
        
        # Convert to UTC if timezone-aware, otherwise assume UTC
        if alert_dt.tzinfo is not None:
            alert_dt = alert_dt.replace(tzinfo=None)  # Remove timezone info after parsing
        
    except (ValueError, TypeError) as e:
        return f"Error: Invalid timestamp format '{alert_timestamp}'. Use ISO 8601 format (e.g., 2026-01-19T11:06:52Z or 2026-01-19T11:06:52.384000+00:00). Details: {str(e)}"

    start_dt = alert_dt - timedelta(minutes=window_minutes)
    end_dt = alert_dt + timedelta(minutes=window_minutes)
    
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    query = {
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}}
                ],
                "must_not": [
                    {"match": {"message": "Non-zero metrics in the last 30s"}}
                ]
            }
        }
    }
    
    try:
        response = client.post("/logs-*/_search", payload=query)
        hits = response.get("hits", {}).get("hits", [])
        
        if not hits:
            return f"No logs found for host '{host_name}' between {start_iso} and {end_iso}."
            
        # Minify logic for the LLM
        summary_lines = []
        for hit in hits:
            src = hit.get("_source", {})
            msg = src.get("message", "No message")
            ts = src.get("@timestamp", "Unknown time")
            event = src.get("event", {}).get("action", "unknown-action")
            process = src.get("process", {}).get("name", "")
            summary_lines.append(f"[{ts}] {event}: {msg} (Proc: {process})")
            
        return f"Found {len(hits)} logs for {host_name}:\n" + "\n".join(summary_lines)
        
    except Exception as e:
        return f"Error querying SIEM: {str(e)}"
