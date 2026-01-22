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

def get_process_tree(host_name: str, process_name: str, alert_timestamp: str) -> str:
    """Analyze process ancestry for a specific process on a host."""
    client = ElasticClient()
    start_iso, end_iso = get_time_range(alert_timestamp, 30)
    query = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                    {"bool": {"should": [{"match": {"process.name": process_name}}, {"match": {"process.parent.name": process_name}}]}}
                ]
            }
        }
    }
    try:
        resp = client.post("/logs-*/_search", payload=query)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits: return f"No process tree data found for {process_name} on {host_name}."
        tree = [f"[{h['_source']['@timestamp']}] {h['_source'].get('process', {}).get('parent', {}).get('name', 'N/A')} -> {h['_source'].get('process', {}).get('name', 'N/A')} (PID: {h['_source'].get('process', {}).get('pid', 'N/A')})" for h in hits]
        return f"Process Tree for {process_name}:\n" + "\n".join(tree[:10])
    except Exception as e: return f"Error: {str(e)}"
