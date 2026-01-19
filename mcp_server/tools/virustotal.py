from typing import Dict, Any, Optional
import os
import requests

def lookup_indicator(indicator: str, type: str = "auto") -> str:
    """
    Check VirusTotal for an indicator (IP, Domain, File Hash).
    
    Args:
        indicator: The IP, Domain, or Hash to check.
        type: One of 'auto', 'ip', 'domain', 'hash'. If 'auto', tries to guess.
        
    Returns:
        A formatted string summary of the reputation.
    """
    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        return "Error: VT_API_KEY not configured."
        
    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}
    
    # Auto-detect type
    if type == "auto":
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
            type = "ip"
        elif len(indicator) in [32, 40, 64] and not "." in indicator:
            type = "hash"
        else:
            type = "domain"
            
    endpoint = ""
    if type == "ip":
        endpoint = f"ip_addresses/{indicator}"
    elif type == "domain":
        endpoint = f"domains/{indicator}"
    elif type == "hash":
        endpoint = f"files/{indicator}"
    else:
        return f"Error: Unknown indicator type '{type}' for '{indicator}'"
        
    try:
        resp = requests.get(f"{base_url}/{endpoint}", headers=headers, timeout=15)
        if resp.status_code == 404:
            return f"{type.upper()} {indicator} not found in VirusTotal."
        resp.raise_for_status()
        data = resp.json()
        
        # Parse attributes
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        tags = attrs.get("tags", [])
        
        verdict = "BENIGN"
        if malicious > 0 or suspicious > 0:
            verdict = "MALICIOUS/SUSPICIOUS"
            
        return (f"VirusTotal {type.upper()}: {indicator}\n"
                f"Verdict: {verdict}\n"
                f"Stats: {malicious} malicious, {suspicious} suspicious, {stats.get('harmless', 0)} harmless.\n"
                f"Tags: {', '.join(tags)}\n"
                f"Last Analysis: {attrs.get('last_analysis_date', 'Unknown')}")
                
    except Exception as e:
        return f"Error querying VirusTotal: {str(e)}"
