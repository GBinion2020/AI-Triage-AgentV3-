from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import os
import sys
from dateutil import parser as dateutil_parser

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from elastic.client import ElasticClient

def get_time_range(timestamp: str, window_minutes: int):
    alert_dt = dateutil_parser.isoparse(timestamp)
    if alert_dt.tzinfo is not None:
        alert_dt = alert_dt.replace(tzinfo=None)
    start_dt = alert_dt - timedelta(minutes=window_minutes)
    end_dt = alert_dt + timedelta(minutes=window_minutes)
    return start_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", end_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def powershell_deep_dive(host_name: str, alert_timestamp: str) -> str:
    """Investigate PowerShell script block logs and command history."""
    client = ElasticClient()
    start_iso, end_iso = get_time_range(alert_timestamp, 30)
    query = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                    {"match": {"process.name": "powershell.exe"}}
                ]
            }
        }
    }
    try:
        resp = client.post("/winlogbeat-*/_search", payload=query) # Specifically target winlogbeat for script blocks
        hits = resp.get("hits", {}).get("hits", [])
        if not hits: return f"No detailed PowerShell logs found for {host_name} in winlogbeat."
        scripts = [f"[{h['_source']['@timestamp']}] {h['_source'].get('powershell', {}).get('command', {}).get('value', 'N/A')}" for h in hits]
        return "PowerShell Deep Dive:\n" + "\n".join(scripts[:10])
    except Exception as e: return f"Error: {str(e)}"
