from typing import List, Dict, Any
import re
from schemas.state import InvestigationState

class DeterministicPlanner:
    """
    Step 8: Deterministic Tool Planner.
    Translates High-Level Intent or MITRE Techniques into concrete Tool Calls.
    """
    
    def _resolve_time_window(self, intent: str, default_back: int = 30, default_forward: int = 30) -> Dict[str, int]:
        """
        Parse time window hints from intent. Returns back/forward minutes.
        """
        intent = intent.lower()
        back = default_back
        forward = default_forward

        # Patterns like "back 30", "forward 60"
        back_match = re.search(r"(back|before|prior)\s+(\d+)\s*(m|min|mins|minutes|h|hr|hrs|hours)", intent)
        fwd_match = re.search(r"(forward|after|next)\s+(\d+)\s*(m|min|mins|minutes|h|hr|hrs|hours)", intent)

        def _to_minutes(value: str, unit: str) -> int:
            n = int(value)
            return n * 60 if unit.startswith("h") else n

        if back_match:
            back = _to_minutes(back_match.group(2), back_match.group(3))
        if fwd_match:
            forward = _to_minutes(fwd_match.group(2), fwd_match.group(3))

        # Patterns like "last 45 minutes" or "past 2 hours"
        range_match = re.search(r"(last|past)\s+(\d+)\s*(m|min|mins|minutes|h|hr|hrs|hours)", intent)
        if range_match:
            minutes = _to_minutes(range_match.group(2), range_match.group(3))
            back = minutes
            forward = 0

        # Clamp to avoid overly broad queries
        back = min(max(5, back), 120)
        forward = min(max(0, forward), 120)

        return {"window_back_minutes": back, "window_forward_minutes": forward}

    def _consecutive_empty_siem(self, state: InvestigationState) -> int:
        count = 0
        for record in reversed(state.tool_history):
            if record.tool_name != "query_siem_host_logs":
                continue
            if record.status != "success":
                continue
            try:
                import json
                payload = json.loads(record.result_summary or "{}")
                results = payload.get("results", {})
                if results.get("count", 0) == 0:
                    count += 1
                else:
                    break
            except Exception:
                break
        return count

    def _adaptive_time_window(self, intent: str, state: InvestigationState) -> Dict[str, int]:
        empty_streak = self._consecutive_empty_siem(state)
        if empty_streak >= 2:
            return self._resolve_time_window(intent, default_back=60, default_forward=60)
        if empty_streak == 1:
            return self._resolve_time_window(intent, default_back=45, default_forward=45)
        return self._resolve_time_window(intent, default_back=15, default_forward=15)

    def _collect_anchor_text(self, state: InvestigationState) -> str:
        parts = []
        rc = state.alert.raw_context
        if rc:
            for value in [
                rc.message,
                rc.process_command_line,
                rc.event_action,
                rc.event_code,
                rc.event_dataset,
                rc.event_provider,
                rc.host_name,
            ]:
                if value:
                    parts.append(str(value))
            if rc.process_args:
                parts.extend([str(v) for v in rc.process_args if v])
        for ev in state.evidence[-5:]:
            if ev.summary:
                parts.append(str(ev.summary))
        return " ".join(parts).lower()

    def _extract_anchor_terms(self, state: InvestigationState) -> Dict[str, List[str]]:
        anchor_text = self._collect_anchor_text(state)
        processes = set(re.findall(r"\b[\w\.-]+\.exe\b", anchor_text))
        message_terms = set()
        rc = state.alert.raw_context
        if rc:
            for value in [rc.event_action, rc.event_code, rc.event_dataset, rc.event_provider]:
                if value:
                    message_terms.add(str(value).strip().lower())
        return {
            "processes": sorted(processes),
            "message_terms": sorted(message_terms),
        }

    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        iocs = {"ip": [], "domain": [], "hash": []}
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            if ip not in iocs["ip"]:
                iocs["ip"].append(ip)
        for h in re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text):
            if h not in iocs["hash"]:
                iocs["hash"].append(h)
        # Domains only when part of a URL to avoid false positives from code tokens.
        for url in re.findall(r"https?://[^\s'\"<>]+", text, flags=re.IGNORECASE):
            host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]
            host = host.split(":")[0]
            lower_host = host.lower()
            if not lower_host or re.match(r"^\d+\.\d+\.\d+\.\d+$", lower_host):
                continue
            if lower_host.endswith((".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs")):
                continue
            if host not in iocs["domain"]:
                iocs["domain"].append(host)
        return iocs

    def _quote_value(self, value: str) -> str:
        if not value:
            return value
        value = value.strip()
        if value.startswith("\"") and value.endswith("\""):
            return value
        return f"\"{value}\""

    def _extract_terms(self, intent: str) -> Dict[str, List[str]]:
        """
        Extract process names and message keywords from the intent.
        The LLM is expected to include explicit values in backticks or quotes.
        """
        intent_lower = intent.lower()
        process_names = set()
        message_terms = set()

        # Backtick or quoted tokens
        quoted = re.findall(r"[`'\"]([^`'\"]+)[`'\"]", intent)
        for term in quoted:
            term = term.strip()
            if not term:
                continue
            if term.lower().endswith(".exe"):
                process_names.add(term)
            elif len(term) <= 40:
                message_terms.add(term)

        # Direct .exe tokens
        for match in re.findall(r"\b[\w\.-]+\.exe\b", intent_lower):
            process_names.add(match)

        # Normalize casing for process names
        process_names = {p if p.endswith(".exe") else f"{p}.exe" for p in process_names}

        return {
            "process_names": sorted(process_names),
            "message_terms": sorted(message_terms),
        }

    def _infer_dimension(self, intent: str) -> str:
        intent = intent.lower()
        if any(w in intent for w in ["login", "signin", "auth", "entra", "identity", "mfa", "user"]):
            return "identity"
        if any(w in intent for w in ["network", "traffic", "connection", "beacon", "dns", "exfil", "lateral"]):
            return "network"
        if any(w in intent for w in ["virustotal", "reputation", "ti", "ioc", "hash", "domain", "ip"]):
            return "threat_intel"
        if any(w in intent for w in ["process", "execution", "command", "powershell", "autoit", "script"]):
            return "process"
        if any(w in intent for w in ["baseline", "anomaly", "geo", "behavior"]):
            return "behavior"
        return "process"

    def _rotate_dimension(self, state: InvestigationState, preferred: str) -> str:
        # Broad playbook sequencing: ensure coverage across dimensions.
        stage_sequence = ["process", "identity", "network", "threat_intel", "behavior"]
        next_index = len(state.dimension_history)
        if next_index < len(stage_sequence):
            return stage_sequence[next_index]

        # After initial coverage, avoid repeating the same dimension twice in a row.
        if state.dimension_history and state.dimension_history[-1] == preferred:
            for alt in ["identity", "network", "threat_intel", "behavior", "process"]:
                if alt != preferred:
                    return alt
        return preferred

    def plan_by_technique(self, techniques: List[str], state: InvestigationState) -> List[Dict[str, Any]]:
        """
        Initial Plan based on MITRE techniques found in the alert.
        """
        plan = []
        host_name = state.alert.entity.host.hostname if state.alert.entity.host else None
        user = state.alert.entity.user.name if state.alert.entity.user else None
        timestamp = state.alert.alert.timestamp.isoformat()
        window_args = self._resolve_time_window("", default_back=30, default_forward=30)
        
        for tech in techniques:
            # Brute Force / Password Spray
            if tech.startswith("T1110"):
                 if host_name:
                     plan.append({
                         "tool": "query_siem_host_logs",
                         "args": {"host_name": host_name, "alert_timestamp": timestamp, **window_args}
                     })
                     
            # PowerShell / Command Line
            if tech.startswith("T1059"):
                if host_name:
                    plan.append({
                         "tool": "query_siem_host_logs",
                         "args": {"host_name": host_name, "alert_timestamp": timestamp, "process_name": "powershell.exe", **window_args}
                     })
        
        # New Rule: If Network Signal is strong, add host logs check even if no MITRE
        if state.alert.analysis_signals.external_communication and host_name:
             plan.append({
                 "tool": "query_siem_host_logs",
                 "args": {"host_name": host_name, "alert_timestamp": timestamp, **window_args}
             })

        return plan

    def plan_from_intent(self, intent: str, state: InvestigationState) -> List[Dict[str, Any]]:
        """
        Translate LLM Intent ("Check if user logged in") to Tool ("search_entra_logs").
        """
        intent = intent.lower()
        plan = []
        user = state.alert.entity.user.name if state.alert.entity.user else None
        has_user = bool(user)
        host = state.alert.entity.host.hostname if state.alert.entity.host else "target_host"
        ts = state.alert.alert.timestamp.isoformat()
        window_args = self._adaptive_time_window(intent, state)
        extracted = self._extract_terms(intent)
        anchors = self._extract_anchor_terms(state)
        preferred_dimension = self._infer_dimension(intent)
        playbook = ["process", "identity", "network", "threat_intel", "behavior"]
        if 1 <= state.iteration_count <= len(playbook):
            target_dimension = playbook[state.iteration_count - 1]
        else:
            target_dimension = self._rotate_dimension(state, preferred_dimension)
        state.dimension_history.append(target_dimension)

        # IOC-first: if any IOC is present in alert context/evidence, prioritize VT.
        anchor_text = self._collect_anchor_text(state)
        iocs = self._extract_iocs(anchor_text)
        if not iocs["ip"] and not iocs["domain"] and not iocs["hash"]:
            for item in state.ioc_store:
                iocs.setdefault(item.get("type"), [])
                if item.get("value") not in iocs[item.get("type")]:
                    iocs[item.get("type")].append(item.get("value"))
        for ioc_type in ["hash", "domain", "ip"]:
            for value in iocs.get(ioc_type, []):
                if not state.is_duplicate("check_virustotal", {"indicator": value, "type": ioc_type}):
                    plan.append({"tool": "check_virustotal", "args": {"indicator": value, "type": ioc_type}})
                    return plan

        if target_dimension == "identity" or "login" in intent or "signin" in intent or "auth" in intent:
            base_args = {"host_name": host, "alert_timestamp": ts, **window_args}
            candidates = []

            if has_user:
                candidates.append({**base_args, "message_contains": self._quote_value(user)})

            for term in extracted["message_terms"]:
                if term.isdigit() and len(term) in {3, 4}:
                    candidates.append({**base_args, "event_code": self._quote_value(term)})
                elif term.lower() in anchors["message_terms"]:
                    candidates.append({**base_args, "message_contains": self._quote_value(term)})

            rc = state.alert.raw_context
            if rc:
                    if rc.event_code:
                        candidates.append({**base_args, "event_code": self._quote_value(str(rc.event_code))})
                if rc.event_dataset:
                    candidates.append({**base_args, "message_contains": self._quote_value(rc.event_dataset)})
                if rc.event_provider:
                    candidates.append({**base_args, "message_contains": self._quote_value(rc.event_provider)})

            candidates.append(base_args)
            for candidate in candidates:
                if not state.is_duplicate("query_siem_host_logs", candidate):
                    plan.append({"tool": "query_siem_host_logs", "args": candidate})
                    break
            
        if target_dimension in {"process", "network"} or any(w in intent for w in ["process", "execution", "network", "traffic", "exfiltration", "connection", "siem"]):
             base_args = {"host_name": host, "alert_timestamp": ts, **window_args}
             candidates = []

             for proc in extracted["process_names"]:
                 proc_value = self._quote_value(proc)
                 candidates.append({**base_args, "process_args_contains": proc_value})
                 if proc.lower() in anchors["processes"]:
                     candidates.append({**base_args, "process_name": proc_value})

             for term in extracted["message_terms"]:
                 if term.isdigit() and len(term) in {3, 4}:
                     continue
                 if term.lower() in anchors["message_terms"]:
                     candidates.append({**base_args, "message_contains": self._quote_value(term)})

             # Field-aware defaults from alert context
             rc = state.alert.raw_context
             if rc:
                 if rc.event_code:
                     candidates.append({**base_args, "event_code": self._quote_value(str(rc.event_code))})
                 if rc.event_dataset:
                     candidates.append({**base_args, "message_contains": self._quote_value(rc.event_dataset)})
                 if rc.event_provider:
                     candidates.append({**base_args, "message_contains": self._quote_value(rc.event_provider)})

             if "network" in intent or "connection" in intent or "traffic" in intent:
                 candidates.append({**base_args, "event_action": "network_connection"})

             # Always allow a broader host window query as a last resort.
             candidates.append(base_args)

             for candidate in candidates:
                 if not state.is_duplicate("query_siem_host_logs", candidate):
                     plan.append({"tool": "query_siem_host_logs", "args": candidate})
                     break

        # Cross-tool corroboration when possible.
        if target_dimension == "process" and state.ioc_store:
            ioc = next((i for i in state.ioc_store if i.get("type") in {"ip", "domain", "hash"}), None)
            if ioc:
                plan.append({"tool": "check_virustotal", "args": {"indicator": ioc["value"], "type": ioc["type"]}})

        if target_dimension == "threat_intel":
            ioc = next((i for i in state.ioc_store if i.get("type") in {"ip", "domain", "hash"}), None)
            if ioc:
                plan.append({"tool": "check_virustotal", "args": {"indicator": ioc["value"], "type": ioc["type"]}})
            else:
                args = {"host_name": host, "alert_timestamp": ts, **window_args}
                if "http" in anchor_text:
                    args["message_contains"] = self._quote_value("http")
                plan.append({"tool": "query_siem_host_logs", "args": args})

        if target_dimension == "behavior":
            plan.append({"tool": "query_siem_host_logs", "args": {"host_name": host, "alert_timestamp": ts, **window_args}})

        if any(w in intent for w in ["reputation", "malicious", "virustotal", "check ip", "check hash"]):
            # Check for IOCs in alert
            # This is simplified - in prod we would parse IOCs from intent or state
            plan.append({"tool": "check_virustotal", "args": {"indicator": "1.1.1.1", "type": "ip"}})
            
        return plan
