# Signals Engine (High Level)

The Signals Engine applies deterministic logic to raw telemetry to extract behavioral signals used by planning and scoring.

## Signal Categories

### Execution & Process
- living_off_the_land
- scripted_execution
- inline_script_block
- encoded_command
- obfuscation_detected
- process_injection_behavior
- child_process_anomaly
- parent_process_mismatch
- signed_binary_abuse
- unexpected_interpreter
- memory_only_execution
- command_length_anomaly
- execution_from_temp
- execution_from_user_writeable_dir
- process_hollowing_pattern

### Network & C2
- external_communication
- rare_destination
- new_destination_for_host
- beaconing_pattern
- long_lived_connection
- low_and_slow_exfiltration
- dns_tunneling_suspected
- http_method_anomaly
- user_agent_anomaly
- ssl_fingerprint_anomaly
- geo_mismatch
- ip_reputation_risk
- domain_generation_pattern
- proxy_evasion_behavior

### File & Data Handling
- file_staging_detected
- bulk_file_access
- sensitive_file_access
- archive_before_exfil
- temp_archive_creation
- file_extension_masquerade
- unexpected_encryption_activity
- data_compression_detected
- shadow_copy_access
- backup_tampering

### Identity & Authentication
- impossible_travel
- new_country_login
- new_device_login
- mfa_bypass_suspected
- credential_reuse_pattern
- password_spray_pattern
- token_replay_detected
- privilege_escalation
- role_assignment_anomaly
- service_account_misuse
- auth_after_disable

### Cloud & API Abuse
- api_burst_behavior
- automation_detected
- infrastructure_recon
- resource_enumeration
- unusual_api_call_sequence
- iam_policy_weakening
- key_creation_followed_by_use
- public_resource_exposure
- logging_disabled_cloud
- cross_account_access

### User & Insider Behavior
- time_of_day_anomaly
- behavioral_baseline_deviation
- role_behavior_mismatch
- sudden_access_spike
- data_access_before_exit
- new_tool_usage
- copy_paste_bulk_activity
- usb_transfer_detected

### Defense Evasion
- logging_disabled_host
- security_tool_tampering
- amsi_bypass_pattern
- etw_tampering
- sensor_blind_spot_creation
- policy_modification
- audit_log_clear
- tamper_protection_bypass

### Meta / Risk Scoring
- multi_stage_attack
- kill_chain_progression
- repeat_offender_entity
- alert_correlation_hit
- historical_false_positive_match
- threat_actor_overlap
- campaign_pattern_match

## How Signals Are Derived

- Signals are derived from normalized ECS fields in `NormalizedSecurityAlert`.
- The engine uses regex/heuristics over fields such as:
  - process.command_line
  - process.args
  - message
  - event.code
  - winlog.channel
  - host.name / host.ip

## How the LLM Sees Signals

Signals are included in the prompt context as structured flags:
- The LLM receives the boolean signal set with any related metadata.
- These signals guide investigation intent and risk scoring.

Signals are deterministic outputs and do not change based on LLM reasoning.
