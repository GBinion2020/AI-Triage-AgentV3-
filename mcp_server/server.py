from fastmcp import FastMCP
from mcp_server.tools import siem, virustotal, entra, cloudtrail, sandbox

# Initialize the MCP Server
mcp = FastMCP("EnterpriseAgenticSOC")

@mcp.tool()
def query_siem_host_logs(host_name: str, alert_timestamp: str, window_minutes: int = 15) -> str:
    """
    Search Elastic SIEM for logs related to a specific host around a timeframe.
    """
    return siem.query_host_logs(host_name, alert_timestamp, window_minutes)

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

if __name__ == "__main__":
    mcp.run()
