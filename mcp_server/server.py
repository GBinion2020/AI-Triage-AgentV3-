from fastmcp import FastMCP
from mcp_server.tools import siem, virustotal, entra, cloudtrail, sandbox, query_builder, feedback
from mcp_server.SIEM_Quries import (
    process_tree, network_beaconing, persistence_hunt, user_logons,
    powershell_deep_dive, file_tampering, registry_monitor,
    scheduled_tasks, dns_trace, security_events
)

# Initialize the MCP Server
mcp = FastMCP("EnterpriseAgenticSOC")

@mcp.tool()
def query_siem_host_logs(
    host_name: str,
    alert_timestamp: str,
    window_minutes: int = 15,
    window_back_minutes: int = None,
    window_forward_minutes: int = None,
    process_name: str = None,
    event_code: str = None,
    message_contains: str = None,
    source_ip: str = None,
    destination_ip: str = None,
    user_id: str = None,
) -> str:
    """
    Search Elastic SIEM for logs related to a specific host around a timeframe.
    """
    return siem.query_host_logs(
        host_name,
        alert_timestamp,
        window_minutes=window_minutes,
        window_back_minutes=window_back_minutes,
        window_forward_minutes=window_forward_minutes,
        process_name=process_name,
        event_code=event_code,
        message_contains=message_contains,
        source_ip=source_ip,
        destination_ip=destination_ip,
        user_id=user_id,
    )

@mcp.tool()
def query_recent_host_alerts(host_name: str, lookback_hours: int = 24) -> str:
    """
    Search for other alerts on the same host in the last N hours.
    """
    return siem.query_recent_host_alerts(host_name, lookback_hours)

@mcp.tool()
def check_virustotal(indicator: str, type: str = "auto") -> str:
    """
    Check VirusTotal for an indicator (IP, Domain, File Hash).
    Type can be 'auto', 'ip', 'domain', 'hash'.
    """
    return virustotal.lookup_indicator(indicator, type)

@mcp.tool()
def search_entra_logs(user_email: str) -> str:
    """
    Search Entra ID (Azure AD) for sign-in logs and risk events for a user.
    """
    return entra.search_entra_logs(user_email)

@mcp.tool()
def search_cloudtrail(resource_id: str) -> str:
    """
    Search AWS CloudTrail for events related to a resource ID or Access Key.
    """
    return cloudtrail.search_cloudtrail(resource_id)

@mcp.tool()
def submit_sandbox(file_hash: str) -> str:
    """
    Submit a file hash or URL to Cuckoo Sandbox for dynamic analysis.
    """
    return sandbox.submit_file_sandbox(file_hash)

@mcp.tool()
def build_siem_query(filters: List[Dict[str, str]]) -> str:
    """
    Dynamically constructs and executes an Elasticsearch query against 'logs-*'.
    Use this for simple lookups by selecting fields and applying logic (AND, OR, NOT).
    
    Allowed Fields:
    - event.kind, event.category, event.type, event.action, event.dataset
    - host.name
    - user.name
    - process.name, process.pid
    - source.ip, destination.ip
    
    Input format: [{'field': 'host.name', 'value': '...', 'logic': 'AND'}]
    """
    return query_builder.build_siem_query(filters)


# --- Extended SIEM Query Library ---

@mcp.tool()
def get_process_tree(host_name: str, process_name: str, alert_timestamp: str) -> str:
    """Analyze process ancestry for a specific process on a host."""
    return process_tree.get_process_tree(host_name, process_name, alert_timestamp)

@mcp.tool()
def get_network_beaconing(host_name: str, alert_timestamp: str) -> str:
    """Detect repetitive outbound traffic patterns."""
    return network_beaconing.get_network_beaconing(host_name, alert_timestamp)

@mcp.tool()
def hunt_persistence(host_name: str, alert_timestamp: str) -> str:
    """Check for persistence mechanisms like registry keys, services, or scheduled tasks."""
    return persistence_hunt.hunt_persistence(host_name, alert_timestamp)

@mcp.tool()
def get_user_logons(user_name: str, host_name: str, alert_timestamp: str) -> str:
    """Analyze authentication logs for a specific user and host."""
    return user_logons.get_user_logons(user_name, host_name, alert_timestamp)

@mcp.tool()
def powershell_deep_dive(host_name: str, alert_timestamp: str) -> str:
    """Investigate PowerShell script block logs and command history."""
    return powershell_deep_dive.powershell_deep_dive(host_name, alert_timestamp)

@mcp.tool()
def detect_file_tampering(host_name: str, alert_timestamp: str) -> str:
    """Detect mass file modifications or suspicious file creations."""
    return file_tampering.detect_file_tampering(host_name, alert_timestamp)

@mcp.tool()
def monitor_registry_keys(host_name: str, alert_timestamp: str) -> str:
    """Monitor for changes to sensitive registry keys."""
    return registry_monitor.monitor_registry_keys(host_name, alert_timestamp)

@mcp.tool()
def audit_scheduled_tasks(host_name: str, alert_timestamp: str) -> str:
    """Audit the creation or modification of scheduled tasks."""
    return scheduled_tasks.audit_scheduled_tasks(host_name, alert_timestamp)

@mcp.tool()
def trace_dns_activity(host_name: str, alert_timestamp: str) -> str:
    """Trace DNS queries and check for exfiltration or suspicious domains."""
    return dns_trace.trace_dns_activity(host_name, alert_timestamp)

@mcp.tool()
def hunt_security_events(event_id: int, host_name: str, alert_timestamp: str) -> str:
    """Hunt for specific Windows Security Event IDs."""
    return security_events.hunt_security_events(event_id, host_name, alert_timestamp)


@mcp.tool()
def ingest_feedback(alert_id: str, notes: str, verdict: str, artifacts: List[str] = []) -> str:
    """
    Ingests analyst close notes and verdicts into the knowledge base.
    This allows the AI to learn from past manual investigations.
    """
    return feedback.ingest_feedback(alert_id, notes, verdict, artifacts)

if __name__ == "__main__":

    mcp.run()
