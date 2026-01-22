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

def hunt_security_events(event_id: int, host_name: str, alert_timestamp: str) -> str:
    """Hunt for specific Windows Security Event IDs."""
    client = ElasticClient()
    start_iso, end_iso = get_time_range(alert_timestamp, 60)
    query = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.code": str(event_id)}},
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}}
                ]
            }
        }
    }
    try:
        resp = client.post("/winlogbeat-*/_search", payload=query)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits: return f"No events found for ID {event_id} on {host_name}."
        evs = [f"[{h['_source']['@timestamp']}] {h['_source'].get('message', 'N/A')[:200]}..." for h in hits]
        return f"Security Event Hunt (ID {event_id}):\n" + "\n".join(evs[:10])
    except Exception as e: return f"Error: {str(e)}"
