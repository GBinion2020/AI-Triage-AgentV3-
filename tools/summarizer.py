from schemas.state import Evidence, EvidenceType

class ResultSummarizer:
    """
    Step 10: Tool Result Summarizer.
    Structure the raw output into Evidence.
    """
    
    def _truncate(self, value: str, max_len: int = 160) -> str:
        if value is None:
            return ""
        if len(value) <= max_len:
            return value
        return value[:max_len] + "..."

    def _format_event_snippet(self, event: dict) -> str:
        ts = event.get("timestamp", "unknown-time")
        action = event.get("event_action", "unknown-action")
        proc = event.get("process_name", "")
        msg = event.get("message", "")
        cmd = event.get("process_command_line", "")
        bits = [f"[{ts}] {action}"]
        if proc:
            bits.append(f"proc={proc}")
        if cmd:
            bits.append(f"cmd={self._truncate(cmd, 140)}")
        if msg:
            bits.append(f"msg={self._truncate(msg, 140)}")
        return " ".join(bits)

    def summarize(self, tool_name: str, raw_output: str) -> Evidence:
        """
        Convert raw string -> Evidence object with both raw and summary fields.
        """
        import re
        import json
        
        # 1. Determine Evidence Type
        ev_type = EvidenceType.LOG
        if raw_output.startswith("Error"):
             ev_type = EvidenceType.ERROR
        elif "Verdict: MALICIOUS" in raw_output:
             ev_type = EvidenceType.IOC
             
        # 2. Heuristic Summarization (Fast, No LLM Latency)
        summary = "No summary available."

        parsed = None
        if isinstance(raw_output, str):
            try:
                parsed = json.loads(raw_output)
            except Exception:
                parsed = None
        
        if tool_name == "query_siem_host_logs":
            if isinstance(parsed, dict) and "key_events" in parsed:
                qc = parsed.get("query_context", {}) or {}
                time_range = qc.get("time_range", {}) or {}
                host = qc.get("host_name", "unknown-host")
                count = parsed.get("results", {}).get("count", 0)
                truncated = parsed.get("results", {}).get("truncated", False)
                events = parsed.get("key_events", [])
                snippets = [self._format_event_snippet(e) for e in events[:3]]
                trunc_note = " (truncated)" if truncated else ""
                summary = (
                    f"SIEM host logs for {host} between {time_range.get('start', 'unknown')} "
                    f"and {time_range.get('end', 'unknown')}. Results: {count}{trunc_note}. "
                    f"Key events: {' | '.join(snippets) if snippets else 'none'}."
                )
            else:
                # Extract process names or interesting events
                procs = re.findall(r"Proc: ([\w\.\-]+)", raw_output)
                events = re.findall(r"\] ([\w\-:\ ]+):", raw_output)
                unique_procs = list(set(procs))
                unique_events = list(set(events))
                summary = (
                    f"SIEM log analysis for host. Found activities: {', '.join(unique_events[:3])}. "
                    f"Processes involved: {', '.join(unique_procs[:3])}."
                )
            
        elif tool_name == "check_virustotal":
            # VirusTotal Hash/IP Verdict: MALICIOUS. Stats: 5 malicious, 2 suspicious.
            verdict_match = re.search(r"Verdict: ([\w/]+)", raw_output)
            stats_match = re.search(r"Stats: (.*)", raw_output)
            verdict = verdict_match.group(1) if verdict_match else "Unknown"
            stats = stats_match.group(1) if stats_match else ""
            summary = f"VirusTotal reputation check. Verdict: {verdict}. {stats}"
            
        elif tool_name == "search_entra_logs":
            summary = "Identity/Auth log summary extracted from Entra."
        
        elif tool_name == "query_recent_host_alerts":
            if isinstance(parsed, dict) and "alerts" in parsed:
                qc = parsed.get("query_context", {}) or {}
                count = parsed.get("results", {}).get("count", 0)
                alerts = parsed.get("alerts", [])
                names = [a.get("rule_name") for a in alerts if a.get("rule_name")]
                summary = (
                    f"Recent alerts for {qc.get('host_name', 'unknown-host')} in last "
                    f"{qc.get('lookback_hours', 24)}h: {count}. "
                    f"Top rules: {', '.join(names[:3]) if names else 'none'}."
                )
        
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
