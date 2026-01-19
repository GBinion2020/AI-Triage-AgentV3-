import re
from typing import Optional
from schemas.alert import AnalysisSignals

class SignalEngine:
    """
    Deterministic logic to derive AnalysisSignals from alert data.
    """
    
    # --- Category A: Execution & Process ---
    LOTL_BINARIES = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", 
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"
    }
    
    TEMP_DIRS = {"\\temp\\", "\\tmp\\", "\\appdata\\local\\temp"}
    
    # --- Category B: Network ---
    EXTERNAL_COMM_KEYWORDS = {
        "Invoke-WebRequest", "iwr", "curl", "wget", "DownloadString", "DownloadFile",
        "System.Net.WebClient", "System.Net.Http", "Start-BitsTransfer"
    }

    # --- Category C: File Staging ---
    FILE_STAGING_KEYWORDS = {
        "Add-Content", "Set-Content", "Get-Content", "Out-File", 
        ">", ">>", "$env:TEMP", "$env:TMP", "Write-Output"
    }
    
    # --- Category G: Defense Evasion ---
    AMSI_KEYWORDS = {"amsiutils", "amsicontext", "amsiinitfailed", "system.management.automation.amsi"}
    LOGGING_DISABLE_KEYWORDS = {"set-mppreference", "disable-iologging", "wevtutil", "cl", "clear-eventlog"}
    
    def derive(self, alert_data: dict, process_name: str, command_line: str) -> AnalysisSignals:
        """
        Derive signals based on raw inputs before the Pydantic object is fully formed.
        """
        signals = AnalysisSignals()
        
        cmd_lower = command_line.lower() if command_line else ""
        proc_lower = process_name.lower() if process_name else ""
        
        # --- A. Execution ---
        if proc_lower in self.LOTL_BINARIES or any(b in cmd_lower for b in self.LOTL_BINARIES):
            signals.living_off_the_land = True
            
        if "{" in command_line and "}" in command_line: # Basic block
            signals.scripted_execution = True
        if ".ps1" in cmd_lower or ".vbs" in cmd_lower or ".bat" in cmd_lower:
            signals.scripted_execution = True
        if "-command" in cmd_lower or "-encodedcommand" in cmd_lower or "-enc" in cmd_lower:
             signals.scripted_execution = True
             
        if "-encodedcommand" in cmd_lower or " -enc " in cmd_lower:
            signals.encoded_command = True
            
        if any(td in cmd_lower for td in self.TEMP_DIRS):
            signals.execution_from_temp = True
            
        # --- B. Network ---
        if any(kw.lower() in cmd_lower for kw in self.EXTERNAL_COMM_KEYWORDS):
            signals.external_communication = True
            
        if "post" in cmd_lower:
            signals.http_method = "POST"
        elif "get" in cmd_lower:
            signals.http_method = "GET"
            
        if "-disablekeepalive" in cmd_lower:
            signals.keepalive_disabled = True
            
        # --- C. File Staging ---
        if any(kw.lower() in cmd_lower for kw in self.FILE_STAGING_KEYWORDS):
            signals.file_staging_detected = True
            
        # --- G. Defense Evasion ---
        if any(kw in cmd_lower for kw in self.AMSI_KEYWORDS):
            signals.amsi_bypass_pattern = True
        
        if any(kw in cmd_lower for kw in self.LOGGING_DISABLE_KEYWORDS):
            signals.logging_disabled_host = True

        # --- Confidence Calculation ---
        boost = 0.0
        
        # Deterministic Weights
        if signals.external_communication: boost += 0.2
        if signals.file_staging_detected: boost += 0.15
        if signals.keepalive_disabled: boost += 0.3 # Strong indicator
        if signals.encoded_command: boost += 0.2
        if signals.amsi_bypass_pattern: boost += 0.4 # Very strong
        if signals.logging_disabled_host: boost += 0.3
        
        # Meta-check from Rule Name (Heuristic)
        rule_name = alert_data.get("kibana", {}).get("alert", {}).get("rule", {}).get("name", "").lower()
        if "apt" in rule_name: boost += 0.2
        if "cobalt strike" in rule_name: boost += 0.3
        
        signals.confidence_boost = round(min(boost, 1.0), 2)
        
        return signals
