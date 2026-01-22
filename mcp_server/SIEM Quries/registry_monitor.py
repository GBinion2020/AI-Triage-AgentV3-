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

def monitor_registry_keys(host_name: str, alert_timestamp: str) -> str:
    """Monitor for changes to sensitive registry keys."""
    client = ElasticClient()
    start_iso, end_iso = get_time_range(alert_timestamp, 60)
    query = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                    {"term": {"event.category": "registry"}}
                ]
            }
        }
    }
    try:
        resp = client.post("/logs-*/_search", payload=query)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits: return f"No registry modifications detected on {host_name}."
        regs = [f"[{h['_source']['@timestamp']}] {h['_source'].get('registry', {}).get('path', 'N/A')} changed to {h['_source'].get('registry', {}).get('value', 'N/A')}" for h in hits]
        return "Registry Monitor Results:\n" + "\n".join(regs[:10])
    except Exception as e: return f"Error: {str(e)}"
