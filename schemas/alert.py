from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class AlertInfo(BaseModel):
    id: str
    name: str
    severity: str = Field(..., description="low, medium, high, critical")
    risk_score: float
    status: str = Field("open", description="open, active, closed")
    timestamp: datetime
    category: str
    description: str = Field("", description="Alert description")
    type: str = "signal"

class DetectionInfo(BaseModel):
    rule_id: str
    rule_type: str = Field("query", description="query, ml, behavioral, threshold")
    query_logic: List[str] = []
    confidence_tags: List[str] = []
    mitre_techniques: List[str] = []
    references: List[str] = []

class ProcessInfo(BaseModel):
    name: str
    pid: Optional[int] = None
    command_line: str
    args: List[str] = []

class PowerShellInfo(BaseModel):
    engine_version: Optional[str] = None
    runspace_id: Optional[str] = None
    engine_state: Dict[str, Optional[str]] = Field(default_factory=dict)

class ExecutionInfo(BaseModel):
    process: Optional[ProcessInfo] = None
    powershell: Optional[PowerShellInfo] = None

class HostInfo(BaseModel):
    hostname: str
    os: str
    os_version: Optional[str] = None
    os_kernel: Optional[str] = None
    os_platform: Optional[str] = None
    os_name_text: Optional[str] = None
    architecture: Optional[str] = None
    ip_addresses: List[str] = []
    mac_addresses: List[str] = []

class UserInfo(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None

class EntityInfo(BaseModel):
    host: Optional[HostInfo] = None
    user: Optional[UserInfo] = None

class AnalysisSignals(BaseModel):
    """
    Deterministic behavioral signals derived from raw telemetry.
    Matches the 50+ signal taxonomy.
    """
    # A. Execution & Process
    living_off_the_land: bool = False
    scripted_execution: bool = False
    inline_script_block: bool = False
    encoded_command: bool = False
    obfuscation_detected: bool = False
    process_injection_behavior: bool = False
    child_process_anomaly: bool = False
    parent_process_mismatch: bool = False
    signed_binary_abuse: bool = False
    unexpected_interpreter: bool = False
    memory_only_execution: bool = False
    command_length_anomaly: bool = False
    execution_from_temp: bool = False
    execution_from_user_writeable_dir: bool = False
    process_hollowing_pattern: bool = False

    # B. Network & C2
    external_communication: bool = False
    rare_destination: bool = False
    new_destination_for_host: bool = False
    beaconing_pattern: bool = False
    long_lived_connection: bool = False
    low_and_slow_exfiltration: bool = False
    dns_tunneling_suspected: bool = False
    http_method_anomaly: bool = False
    user_agent_anomaly: bool = False
    ssl_fingerprint_anomaly: bool = False
    geo_mismatch: bool = False
    ip_reputation_risk: bool = False
    domain_generation_pattern: bool = False
    proxy_evasion_behavior: bool = False
    
    # Specifics for context
    http_method: Optional[str] = None
    keepalive_disabled: Optional[bool] = None
    external_destination: Optional[str] = None

    # C. File & Data Handling
    file_staging_detected: bool = False
    bulk_file_access: bool = False
    sensitive_file_access: bool = False
    archive_before_exfil: bool = False
    temp_archive_creation: bool = False
    file_extension_masquerade: bool = False
    unexpected_encryption_activity: bool = False
    data_compression_detected: bool = False
    shadow_copy_access: bool = False
    backup_tampering: bool = False

    # D. Identity & Authentication
    impossible_travel: bool = False
    new_country_login: bool = False
    new_device_login: bool = False
    mfa_bypass_suspected: bool = False
    credential_reuse_pattern: bool = False
    password_spray_pattern: bool = False
    token_replay_detected: bool = False
    privilege_escalation: bool = False
    role_assignment_anomaly: bool = False
    service_account_misuse: bool = False
    auth_after_disable: bool = False

    # E. Cloud & API Abuse
    api_burst_behavior: bool = False
    automation_detected: bool = False
    infrastructure_recon: bool = False
    resource_enumeration: bool = False
    unusual_api_call_sequence: bool = False
    iam_policy_weakening: bool = False
    key_creation_followed_by_use: bool = False
    public_resource_exposure: bool = False
    logging_disabled_cloud: bool = False
    cross_account_access: bool = False

    # F. User & Insider Behavior
    time_of_day_anomaly: bool = False
    behavioral_baseline_deviation: bool = False
    role_behavior_mismatch: bool = False
    sudden_access_spike: bool = False
    data_access_before_exit: bool = False
    new_tool_usage: bool = False
    copy_paste_bulk_activity: bool = False
    usb_transfer_detected: bool = False

    # G. Defense Evasion
    logging_disabled_host: bool = False
    security_tool_tampering: bool = False
    amsi_bypass_pattern: bool = False
    etw_tampering: bool = False
    sensor_blind_spot_creation: bool = False
    policy_modification: bool = False
    audit_log_clear: bool = False
    tamper_protection_bypass: bool = False

    # H. Meta / Risk Scoring
    multi_stage_attack: bool = False
    kill_chain_progression: bool = False
    repeat_offender_entity: bool = False
    alert_correlation_hit: bool = False
    historical_false_positive_match: bool = False
    threat_actor_overlap: bool = False
    campaign_pattern_match: bool = False
    
    confidence_boost: float = 0.0
    confidence_decay: float = 0.0

class RawContext(BaseModel):
    """
    Minimal raw alert context needed for triage.
    """
    rule_name: Optional[str] = None
    rule_description: Optional[str] = None
    alert_reason: Optional[str] = None
    message: Optional[str] = None
    event_created: Optional[str] = None
    event_code: Optional[str] = None
    event_action: Optional[str] = None
    event_dataset: Optional[str] = None
    event_provider: Optional[str] = None
    event_category: Optional[Any] = None
    winlog_event_id: Optional[str] = None
    winlog_channel: Optional[str] = None
    winlog_process_pid: Optional[Any] = None
    winlog_computer_name: Optional[str] = None
    agent_name: Optional[str] = None
    host_os_kernel: Optional[str] = None
    host_os_name: Optional[str] = None
    host_name: Optional[str] = None
    host_os_platform: Optional[str] = None
    host_os_name_text: Optional[str] = None
    host_ip: Optional[Any] = None
    host_mac: Optional[Any] = None
    process_command_line: Optional[str] = None
    process_args: Optional[Any] = None
    process_pid: Optional[Any] = None

class NormalizedSecurityAlert(BaseModel):
    """
    New Scheme for normalized alerts.
    Includes deterministic analysis signals.
    """
    alert: AlertInfo
    detection: DetectionInfo
    execution: ExecutionInfo
    entity: EntityInfo
    analysis_signals: AnalysisSignals
    raw_context: Optional[RawContext] = None
    
    # Original raw data kept for reference/debugging
    raw_data: Dict[str, Any] = Field(default_factory=dict)
