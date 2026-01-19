from schemas.state import Evidence, EvidenceType

class ResultSummarizer:
    """
    Step 10: Tool Result Summarizer.
    Structure the raw output into Evidence.
    """
    
    def summarize(self, tool_name: str, raw_output: str) -> Evidence:
        """
        Convert raw string -> Evidence object with both raw and summary fields.
        """
        import re
        
        # 1. Determine Evidence Type
        ev_type = EvidenceType.LOG
        if raw_output.startswith("Error"):
             ev_type = EvidenceType.ERROR
        elif "Verdict: MALICIOUS" in raw_output:
             ev_type = EvidenceType.IOC
             
        # 2. Heuristic Summarization (Fast, No LLM Latency)
        summary = "No summary available."
        
        if tool_name == "query_siem_host_logs":
            # Extract process names or interesting events
            procs = re.findall(r"Proc: ([\w\.\-]+)", raw_output)
            events = re.findall(r"\] ([\w\-:\ ]+):", raw_output)
            unique_procs = list(set(procs))
            unique_events = list(set(events))
            summary = f"SIEM log analysis for host. Found activities: {', '.join(unique_events[:3])}. Processes involved: {', '.join(unique_procs[:3])}."
            
        elif tool_name == "check_virustotal":
            # VirusTotal Hash/IP Verdict: MALICIOUS. Stats: 5 malicious, 2 suspicious.
            verdict_match = re.search(r"Verdict: ([\w/]+)", raw_output)
            stats_match = re.search(r"Stats: (.*)", raw_output)
            verdict = verdict_match.group(1) if verdict_match else "Unknown"
            stats = stats_match.group(1) if stats_match else ""
            summary = f"VirusTotal reputation check. Verdict: {verdict}. {stats}"
            
        elif tool_name == "search_entra_logs":
            summary = "Identity/Auth log summary extracted from Entra."
        
        else:
            # Fallback: truncate
            summary = raw_output[:200] + "..." if len(raw_output) > 200 else raw_output

        # 3. Create Evidence
        return Evidence(
            content=raw_output, 
            summary=summary,
            source_tool=tool_name,
            type=ev_type,
            confidence=1.0
        )
