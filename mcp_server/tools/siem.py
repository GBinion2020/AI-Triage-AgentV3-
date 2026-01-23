from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import os
import sys
from dateutil import parser as dateutil_parser

# Ensure we can import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from elastic.client import ElasticClient

def _truncate(value: Optional[str], max_len: int = 300) -> str:
    if not value:
        return ""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."

def query_recent_host_alerts(host_name: str, lookback_hours: int = 24) -> dict:
    """
    Search alert index for other alerts on the same host in the last N hours.
    """
    client = ElasticClient()
    query = {
        "size": 20,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host_name}},
                    {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h"}}}
                ]
            }
        }
    }
    try:
        response = client.post("/.alerts-security.alerts-*/_search", payload=query)
        hits = response.get("hits", {}).get("hits", [])
        alerts = []
        for hit in hits:
            src = hit.get("_source", {})
            rule = src.get("kibana", {}).get("alert", {}).get("rule", {})
            alerts.append({
                "alert_id": hit.get("_id", ""),
                "timestamp": src.get("@timestamp", ""),
                "rule_name": rule.get("name", ""),
                "severity": rule.get("severity", ""),
                "risk_score": rule.get("risk_score", ""),
                "reason": src.get("kibana", {}).get("alert", {}).get("reason", ""),
            })
        return {
            "query_context": {
                "host_name": host_name,
                "lookback_hours": lookback_hours,
                "max_results": 20
            },
            "results_count": len(hits),
            "alerts": alerts
        }
    except Exception as e:
        return f"Error querying SIEM alerts: {str(e)}"

def query_host_logs(
    host_name: str,
    alert_timestamp: str,
    window_minutes: int = 15,
    window_back_minutes: Optional[int] = None,
    window_forward_minutes: Optional[int] = None,
    process_name: Optional[str] = None,
    event_code: Optional[str] = None,
    message_contains: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    user_id: Optional[str] = None,
) -> str:
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
    if window_back_minutes is not None or window_forward_minutes is not None:
        back = 15 if window_back_minutes is None else int(window_back_minutes)
        forward = 15 if window_forward_minutes is None else int(window_forward_minutes)
        back = min(max(5, back), 120)
        forward = min(max(0, forward), 120)
    else:
        window_minutes = min(max(5, window_minutes), 120)
        back = window_minutes
        forward = window_minutes
    
    # Date parsing - support multiple ISO 8601 formats including timezone offsets
    try:
        # Use dateutil parser for robust ISO 8601 parsing (handles +00:00, Z, etc.)
        alert_dt = dateutil_parser.isoparse(alert_timestamp)
        
        # Convert to UTC if timezone-aware, otherwise assume UTC
        if alert_dt.tzinfo is not None:
            alert_dt = alert_dt.replace(tzinfo=None)  # Remove timezone info after parsing
        
    except (ValueError, TypeError) as e:
        return f"Error: Invalid timestamp format '{alert_timestamp}'. Use ISO 8601 format (e.g., 2026-01-19T11:06:52Z or 2026-01-19T11:06:52.384000+00:00). Details: {str(e)}"

    start_dt = alert_dt - timedelta(minutes=back)
    end_dt = alert_dt + timedelta(minutes=forward)
    
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _clean(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = str(value).strip()
        if len(value) >= 2 and value.startswith("\"") and value.endswith("\""):
            return value[1:-1]
        return value

    process_name = _clean(process_name)
    event_code = _clean(event_code)
    message_contains = _clean(message_contains)
    source_ip = _clean(source_ip)
    destination_ip = _clean(destination_ip)
    user_id = _clean(user_id)

    filters = [
        {"term": {"host.name": host_name}},
        {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
    ]
    if process_name:
        filters.append({"match_phrase": {"process.name": process_name}})
    if event_code:
        filters.append({"term": {"event.code": event_code}})
    if message_contains:
        filters.append({"match_phrase": {"message": message_contains}})
    if source_ip:
        filters.append({"term": {"source.ip": source_ip}})
    if destination_ip:
        filters.append({"term": {"destination.ip": destination_ip}})
    if user_id:
        filters.append({"term": {"user.id": user_id}})

    query = {
        "size": 25,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": filters,
                "must_not": [
                    {"match": {"message": "Non-zero metrics in the last 30s"}}
                ]
            }
        }
    }
    
    try:
        response = client.post("/logs-*/_search", payload=query)
        hits = response.get("hits", {}).get("hits", [])

        events: List[Dict[str, Any]] = []
        for hit in hits:
            src = hit.get("_source", {})
            event = src.get("event", {}) or {}
            process = src.get("process", {}) or {}
            user = src.get("user", {}) or {}
            host = src.get("host", {}) or {}
            source = src.get("source", {}) or {}
            destination = src.get("destination", {}) or {}
            file_obj = src.get("file", {}) or {}
            url_obj = src.get("url", {}) or {}
            dns_obj = src.get("dns", {}) or {}
            registry_obj = src.get("registry", {}) or {}
            winlog = src.get("winlog", {}) or {}
            host_os = host.get("os", {}) or {}
            proc_args = process.get("args", [])
            if proc_args and not isinstance(proc_args, list):
                proc_args = [str(proc_args)]
            host_ip = host.get("ip", [])
            if host_ip and not isinstance(host_ip, list):
                host_ip = [host_ip]
            host_mac = host.get("mac", [])
            if host_mac and not isinstance(host_mac, list):
                host_mac = [host_mac]

            events.append({
                "@timestamp": src.get("@timestamp", ""),
                "timestamp": src.get("@timestamp", ""),
                "event_created": event.get("created", ""),
                "event_action": event.get("action", ""),
                "event_code": event.get("code", ""),
                "event_provider": event.get("provider", ""),
                "event_dataset": event.get("dataset", ""),
                "event_category": event.get("category", ""),
                "message": _truncate(src.get("message", "No message"), 350),
                "process_name": process.get("name", ""),
                "process_pid": process.get("pid", ""),
                "process_parent": process.get("parent", {}).get("name", ""),
                "process_executable": process.get("executable", ""),
                "process_command_line": _truncate(process.get("command_line", ""), 350),
                "process_args": proc_args or [],
                "user_name": user.get("name", ""),
                "user_id": user.get("id", ""),
                "host_name": host.get("name", ""),
                "host_ip": host_ip or [],
                "host_mac": host_mac or [],
                "host_os_name": host_os.get("name", ""),
                "host_os_name_text": host_os.get("name.text", ""),
                "host_os_platform": host_os.get("platform", ""),
                "host_os_kernel": host_os.get("kernel", ""),
                "source_ip": source.get("ip", ""),
                "destination_ip": destination.get("ip", ""),
                "file_name": file_obj.get("name", ""),
                "file_hash_sha256": file_obj.get("hash", {}).get("sha256", ""),
                "file_hash_sha1": file_obj.get("hash", {}).get("sha1", ""),
                "file_hash_md5": file_obj.get("hash", {}).get("md5", ""),
                "registry_path": registry_obj.get("path", ""),
                "url_full": url_obj.get("full", ""),
                "dns_question": dns_obj.get("question", {}).get("name", ""),
                "winlog_channel": winlog.get("channel", ""),
                "winlog_process_pid": winlog.get("process", {}).get("pid", "")
            })

        return {
            "query_context": {
                "host_name": host_name,
                "alert_timestamp": alert_timestamp,
                "time_range": {"start": start_iso, "end": end_iso},
                "filters": {
                    "process_name": process_name,
                    "event_code": event_code,
                    "message_contains": message_contains,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "user_id": user_id
                },
                "max_results": 25
            },
            "results_count": len(hits),
            "truncated": len(hits) >= 25,
            "events": events
        }

    except Exception as e:
        return f"Error querying SIEM: {str(e)}"
