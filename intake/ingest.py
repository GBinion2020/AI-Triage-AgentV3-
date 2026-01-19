from typing import List, Optional
from elastic.client import ElasticClient
# New Schema Imports
from schemas.alert import (
    NormalizedSecurityAlert, AlertInfo, DetectionInfo, ExecutionInfo, 
    EntityInfo, ProcessInfo, HostInfo, UserInfo, PowerShellInfo
)
from intake.logic import SignalEngine
from datetime import datetime

class AlertIngestor:
    """
    Fetches raw alerts from Elastic SIEM and normalizes them into NormalizedSecurityAlert objects.
    """
    def __init__(self):
        self.client = ElasticClient()
        self.alert_index = ".alerts-security.alerts-*"
        self.signal_engine = SignalEngine()
        
    def fetch_latest_alerts(self, minutes: int = 60, limit: int = 10) -> List[NormalizedSecurityAlert]:
        """
        Fetch alerts from the last X minutes.
        """
        # Query Elastic
        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}
                    ]
                }
            }
        }
        
        try:
            response = self.client.post(f"/{self.alert_index}/_search", payload=query)
            hits = response.get("hits", {}).get("hits", [])
            
            alerts = []
            for hit in hits:
                source = hit.get("_source", {})
                alert = self._normalize(hit.get("_id"), source)
                if alert:
                    alerts.append(alert)
            return alerts
            
        except Exception as e:
            print(f"Error fetching alerts: {e}")
            return []

    def _normalize(self, alert_id: str, source: dict) -> NormalizedSecurityAlert:
        """
        Map ECS fields to NormalizedSecurityAlert schema.
        Handles both flattened (kibana.alert.*) and nested (signal.*) formats.
        """
        try:
            # Helper to get field from any level
            def get_field(keys: List[str], default=None):
                for k in keys:
                    if k in source:
                        return source[k]
                    # Try nested lookup
                    parts = k.split('.')
                    val = source
                    for p in parts:
                        if isinstance(val, dict):
                            val = val.get(p)
                        else:
                            val = None
                            break
                    if val is not None:
                        return val
                return default

            # --- 1. Alert Info ---
            timestamp = get_field(["@timestamp"])
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            else:
                dt = datetime.now()
                
            rule_name = get_field(["kibana.alert.rule.name", "signal.rule.name", "rule.name"], "Unknown Rule")
            severity = get_field(["kibana.alert.rule.severity", "signal.rule.severity", "rule.severity"], "low")
            risk_score = get_field(["kibana.alert.rule.risk_score", "signal.rule.risk_score", "rule.risk_score"], 0)
            description = get_field(["kibana.alert.rule.description", "signal.rule.description"], rule_name)
            category = get_field(["kibana.alert.rule.category"], "Unknown")
            
            alert_info = AlertInfo(
                id=alert_id,
                name=rule_name,
                severity=severity,
                risk_score=float(risk_score),
                timestamp=dt,
                category=category,
                description=description,
                status="open" 
            )
            
            # --- 2. Detection Info ---
            rule_id = get_field(["kibana.alert.rule.uuid", "signal.rule.id", "rule.id"], "unknown")
            rule_type = get_field(["kibana.alert.rule.type"], "query")
            refs = get_field(["kibana.alert.rule.references"], [])
            
            # Extract MITRE from tags (ECS common pattern)
            tags = get_field(["tags", "kibana.alert.tags"], [])
            mitre = [t for t in tags if t.startswith("T")] 
            
            detection_info = DetectionInfo(
                rule_id=rule_id,
                rule_type=rule_type,
                references=refs,
                mitre_techniques=mitre 
            )
            
            # --- 3. Execution Info ---
            proc_name = get_field(["process.name", "process.executable", "kibana.alert.original_event.process.name"])
            cmd_line = get_field(["process.command_line", "process.args"], "")
            if isinstance(cmd_line, list): 
                cmd_line = " ".join(cmd_line)
                
            process_info = None
            if proc_name:
                process_info = ProcessInfo(
                    name=proc_name,
                    pid=get_field(["process.pid"]),
                    command_line=cmd_line or ""
                )
                
            # Populating Powershell info if available (ECS fields)
            ps_version = get_field(["powershell.version", "process.powershell.version"])
            runspace = get_field(["powershell.runspace_id"])
            
            ps_info = None
            if ps_version or runspace:
                ps_info = PowerShellInfo(
                    engine_version=ps_version,
                    runspace_id=runspace
                )
            
            execution_info = ExecutionInfo(
                process=process_info,
                powershell=ps_info
            )
            
            # --- 4. Entity Info ---
            host_name = get_field(["host.name", "host.hostname"])
            host_ip = get_field(["host.ip"], [])
            if host_ip and not isinstance(host_ip, list): host_ip = [host_ip]
            
            host_info = None
            if host_name:
                host_info = HostInfo(
                    hostname=host_name,
                    os=get_field(["host.os.name", "host.os.full"], "Unknown"),
                    ip_addresses=host_ip or []
                )
                
            user_name = get_field(["user.name", "user.id"])
            user_info = None
            if user_name:
                user_info = UserInfo(
                    name=user_name,
                    id=get_field(["user.id"])
                )
                
            entity_info = EntityInfo(
                host=host_info,
                user=user_info
            )
            
            # --- 5. Analysis Signals (Deterministic) ---
            # We pass the raw dict and extracted command line for signal derivation
            signals = self.signal_engine.derive(
                alert_data=source,
                process_name=proc_name,
                command_line=cmd_line
            )
            
            # --- Final Object ---
            normalized_alert = NormalizedSecurityAlert(
                alert=alert_info,
                detection=detection_info,
                execution=execution_info,
                entity=entity_info,
                analysis_signals=signals,
                raw_data=source
            )
            
            return normalized_alert
            
        except Exception as e:
            print(f"Error normalizing alert {alert_id}: {e}")
            import traceback
            traceback.print_exc()
            return None
