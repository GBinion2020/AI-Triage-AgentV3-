# SIEM Query Library: Investigative Capabilities

This document maps the specialized SIEM query tools to their investigative purposes in a SOC workflow.

| Tool Name | Function | Investigative Purpose |
|-----------|----------|------------------------|
| `process_tree` | `get_process_tree` | Analyzes parent-child relationships to identify the source of execution (e.g., cmd.exe launching suspicious binaries). |
| `network_beaconing` | `get_network_beaconing` | Identifies repetitive outbound connections to C2 infrastructure by analyzing traffic volume and timing. |
| `persistence_hunt` | `hunt_persistence` | Scans for persistence mechanisms like "Run" registry keys, scheduled tasks, and service modifications. |
| `user_logons` | `get_user_logons` | Audits authentication logs for a specific user to detect brute force, lateral movement, or unauthorized logins. |
| `powershell_deep_dive` | `powershell_deep_dive` | Investigates script block logs (Winlogbeat) to reveal obfuscated commands or malicious script logic. |
| `file_tampering` | `detect_file_tampering` | Monitors for mass file creations, deletions, or modifications, often associated with ransomware or staging. |
| `registry_monitor` | `monitor_registry_keys` | Tracks changes to sensitive registry hives (HKLM, HKCU) for configuration tampering or credential theft. |
| `scheduled_tasks` | `audit_scheduled_tasks` | Audits `schtasks.exe` usage and Task Scheduler logs for malicious task registration. |
| `dns_trace` | `trace_dns_activity` | Analyzes DNS query logs for DGA domains, DNS tunneling, or exfiltration attempts. |
| `security_events` | `hunt_security_events` | Allows hunting for specific Windows Event IDs (e.g., 4624 for successful logon, 4688 for process creation). |
| `query_builder` | `build_siem_query` | Dynamic query constructor for ad-hoc lookups using ECS fields and boolean logic. |

