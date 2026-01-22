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

def get_network_beaconing(host_name: str, alert_timestamp: str) -> str:
    """Detect repetitive outbound traffic patterns."""
    client = ElasticClient()
    start_iso, end_iso = get_time_range(alert_timestamp, 60)
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                    {"exists": {"field": "destination.ip"}}
                ]
            }
        },
        "aggs": {
            "destinations": {
                "terms": {"field": "destination.ip", "size": 10},
                "aggs": {"hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "5m"}}}
            }
        }
    }
    try:
        resp = client.post("/logs-*/_search", payload=query)
        buckets = resp.get("aggregations", {}).get("destinations", {}).get("buckets", [])
        if not buckets: return f"No beaconing patterns detected for {host_name}."
        results = [f"Dest: {b['key']} | Count: {b['doc_count']}" for b in buckets]
        return "Network Beaconing Analysis:\n" + "\n".join(results)
    except Exception as e: return f"Error: {str(e)}"
