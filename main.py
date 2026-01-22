import os
import sys
import logging
import json
import time
import re
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Components
from intake.ingest import AlertIngestor
from intake.pre_classifier import PreClassifier
from llm.client import LLMClient
from context.builder import build_initial_state
from context.mitre_map import get_mitre_techniques
from context.rag import MitreRAG
from control.policy_engine import PolicyEngine
from control.token_guard import TokenBudgetController
from control.planner import DeterministicPlanner
from tools.executor import ToolExecutor
from tools.summarizer import ResultSummarizer
from agents.intake_agent import IntakeAgent
from agents.investigation_agent import InvestigationAgent
from agents.reasoning_agent import ReasoningAgent
from agents.decision_agent import DecisionAgent
from core.confidence import check_operational_confidence, check_analytical_confidence, label_operational_confidence
from core.scoring import RiskScoringMatrix
from core.risk_factors import build_risk_factors, build_evidence_table, is_conclusive_score
from schemas.state import InvestigationState, LoopAudit
from utils.pipeline_logger import PipelineLogger
from utils.email_notifier import EmailNotifier

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("EnterpriseSOC")

def select_llm_provider():
    """
    Interactive prompt to select LLM provider.
    """
    env_choice = os.getenv("LLM_PROVIDER", "").strip().lower()
    if env_choice in {"local", "external"}:
        return env_choice
    if env_choice in {"1", "2"}:
        return "local" if env_choice == "1" else "external"

    print("\n" + "="*50)
    print("LLM PROVIDER SELECTION")
    print("="*50)
    print("1. Local LLM (Ollama)")
    print("2. External API (OpenAI/Compatible)")
    
    while True:
        choice = input("\nSelect LLM provider [1/2]: ").strip()
        if choice == "1":
            return "local"
        elif choice == "2":
            return "external"
        else:
            print("Invalid choice. Please enter 1 or 2.")

def main():
    logger.info("Starting Enterprise Agentic SOC...")
    
    ingestor = AlertIngestor()
    pre_classifier = PreClassifier()
    
    # 1. Fetch Alerts
    try:
        alerts = ingestor.fetch_latest_alerts(minutes=1440, limit=1) # Last 24h
        logger.info(f"Fetched {len(alerts)} alerts.")
    except Exception as e:
        logger.error(f"Failed to fetch alerts: {e}")
        return

    if not alerts:
        logger.info("No new alerts to process.")
        return

    # 2. Select LLM Provider (Interactive)
    llm_mode = select_llm_provider()
    llm_client = LLMClient(mode=llm_mode)

    # 3. Initialize Agents with Shared LLM Client
    intake_agent = IntakeAgent(llm_client)
    inv_agent = InvestigationAgent(llm_client)
    reason_agent = ReasoningAgent(llm_client)
    decision_agent = DecisionAgent(llm_client)
    
    mitre_rag = MitreRAG()
    policy_engine = PolicyEngine()
    token_guard = TokenBudgetController(max_tokens=60000)
    planner = DeterministicPlanner()
    executor = ToolExecutor()
    summarizer = ResultSummarizer()
    email_notifier = EmailNotifier()

    for alert in alerts:
        process_alert(
            alert, 
            pre_classifier, intake_agent, mitre_rag, policy_engine, 
            token_guard, planner, executor, summarizer, 
            inv_agent, reason_agent, decision_agent,
            email_notifier
        )

def extract_iocs(state: InvestigationState) -> list:
    """
    Strictly extracts verified IOCs from normalized alert fields.
    Investigated IOCs are added by agents during the triage loop.
    """
    iocs = []
    seen_values = set()
    import ipaddress

    def is_public_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except ValueError:
            return False
    
    # 1. Verified infrastructure IOCs (favor external destinations and explicit indicators)
    if state.alert.analysis_signals.external_destination:
        dest = state.alert.analysis_signals.external_destination
        if dest not in seen_values:
            ioc_type = "domain" if "." in dest and not is_public_ip(dest) else "ip"
            if ioc_type == "domain" or is_public_ip(dest):
                iocs.append({"type": ioc_type, "value": dest, "source": "verified_initial"})
                seen_values.add(dest)

    # Extract IOCs from alert description if present
    description = state.alert.alert.description or ""
    if description:
        ip_regex = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
        hash_regex = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
        domain_regex = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        for ip in re.findall(ip_regex, description):
            if ip not in seen_values:
                if is_public_ip(ip):
                    iocs.append({"type": "ip", "value": ip, "source": "alert_description"})
                    seen_values.add(ip)
        for h in re.findall(hash_regex, description):
            if h not in seen_values:
                iocs.append({"type": "hash", "value": h, "source": "alert_description"})
                seen_values.add(h)
        for domain in re.findall(domain_regex, description):
            if domain not in seen_values:
                iocs.append({"type": "domain", "value": domain, "source": "alert_description"})
                seen_values.add(domain)

    # Note: We rely on state.ioc_store to accumulate artifacts found 
    # by agents in their 'intent' or 'reasoning' responses.
    
    return iocs

def update_ioc_store(state: InvestigationState, llm_response: str, agent_name: str):
    """
    Parses LLM responses for structured IOC markers and updates the state.
    Format expected: [IOC: type value] e.g. [IOC: ip 1.2.3.4]
    """
    if not llm_response: return
    
    # Regex to find [IOC: type value]
    ioc_regex = r'\[IOC:\s*(\w+)\s+([^\s\]]+)\]'
    matches = re.findall(ioc_regex, llm_response, re.IGNORECASE)
    
    for ioc_type, ioc_value in matches:
        normalized_type = ioc_type.lower()
        if normalized_type not in {"ip", "domain", "hash"}:
            continue
        # Check for duplicates in state
        exists = any(i['value'].lower() == ioc_value.lower() for i in state.ioc_store)
        if not exists:
            state.ioc_store.append({
                "type": normalized_type,
                "value": ioc_value,
                "source": f"llm_discovery ({agent_name})"
            })
            logger.info(f"LLM Discovered New IOC ({agent_name}): {ioc_type}={ioc_value}")

def process_alert(alert, pre_classifier, intake_agent, mitre_rag, policy_engine, token_guard, planner, executor, summarizer, inv_agent, reason_agent, decision_agent, email_notifier):
    logger.info(f"Processing Alert: {alert.alert.name} (ID: {alert.alert.id})")
    
    # Initialize Pipeline Logger
    pipeline_log = PipelineLogger(alert.alert.id)
    pipeline_log.log_section("ALERT PROCESSING STARTED")
    pipeline_log.log_step("ALERT_INFO", f"Name: {alert.alert.name}\n   Severity: {alert.alert.severity}\n   Risk Score: {alert.alert.risk_score}")
    
    # --- Step 2: Pre-Classification ---
    pipeline_log.log_step("PRE_CLASSIFICATION", "Running deterministic pre-classifier...")
    decision, reason = pre_classifier.classify(alert)
    pipeline_log.log_step("PRE_CLASSIFICATION_RESULT", f"Decision: {decision}\n   Reason: {reason}")
    
    if decision != "investigate":
        logger.info(f"Alert closed by Pre-Classifier: {decision} ({reason})")
        pipeline_log.log_step("ALERT_CLOSED", f"Alert closed by pre-classifier: {decision}")
        pipeline_log.close()
        return # Done
        
    # --- Step 3: Build Context (Moved up for historical grounding) ---
    pipeline_log.log_step("CONTEXT_BUILD", "Building initial investigation state including historical lessons...")
    state = build_initial_state(alert)
    # Initialize Verified IOCs from Metadata
    state.ioc_store = extract_iocs(state)
    pipeline_log.log_step("CONTEXT_BUILD_COMPLETE", "Investigation state initialized and verified IOCs extracted")

    # --- Step 2b: Intake Agent (Now grounded in Feedback RAG) ---
    agent_start = pipeline_log.log_agent_start("IntakeAgent", "Evaluating alert for initial triage with historical context")
    start_time = time.time()
    intake_decision = intake_agent.evaluate(state) # Passed 'state' instead of 'alert'
    elapsed = time.time() - start_time
    logger.info(f"Intake Agent took {elapsed:.2f}s")
    pipeline_log.log_agent_end("IntakeAgent", agent_start, f"Decision: {intake_decision}")
    
    if intake_decision == "close_benign":
        logger.info("Alert closed by Intake Agent as Benign.")
        pipeline_log.log_step("ALERT_CLOSED", "Alert closed by Intake Agent as benign")
        pipeline_log.close()
        return # Done
    
    # --- Step 4: MITRE Map ---
    pipeline_log.log_step("MITRE_MAPPING", "Mapping alert to MITRE ATT&CK techniques...")
    techniques = get_mitre_techniques(alert.alert.name, alert.alert.id)
    
    # Conditional RAG (Step 5)
    if not techniques:
        logger.info("Low confidence in deterministic map. Querying RAG...")
        pipeline_log.log_step("RAG_QUERY", "Deterministic mapping failed, querying RAG...")
        rag_results = mitre_rag.query(f"{alert.alert.name} {alert.alert.description}")
        for res in rag_results:
            techniques.append(res['id'])
            logger.info(f"RAG found technique: {res['id']} ({res['name']})")
            pipeline_log.log_step("RAG_RESULT", f"Found technique: {res['id']} - {res['name']}")
    
    state.alert.detection.mitre_techniques = techniques
    logger.info(f"Final Mapped Techniques: {techniques}")
    pipeline_log.log_data("MITRE_TECHNIQUES", techniques)
    
    # --- Loop: Investigation ---
    pipeline_log.log_section("INVESTIGATION LOOP")
    max_loops = 10
    final_reasoning = ""
    
    while state.iteration_count < max_loops:
        state.iteration_count += 1
        logger.info(f"--- Iteration {state.iteration_count} ---")
        pipeline_log.log_iteration(state.iteration_count, max_loops)
        
        # Initialize Loop Audit
        current_audit = LoopAudit(
            iteration=state.iteration_count,
            intent="Initializing loop",
            tools_planned=[]
        )

        # Host alert history query on first loop: last 24 hours
        if state.iteration_count == 1 and not state.evidence:
            host_name = alert.entity.host.hostname if alert.entity.host else ""
            if host_name:
                history_args = {"host_name": host_name, "lookback_hours": 24}
                pipeline_log.log_step("HOST_ALERT_HISTORY", "Running host alert history query (last 24h).")
                policy = policy_engine.check_tool_permission(state, "query_recent_host_alerts", history_args)
                if policy.allowed:
                    tool_start = time.time()
                    raw_result = executor.execute("query_recent_host_alerts", history_args)
                    tool_elapsed = time.time() - tool_start
                    status = "success" if not raw_result.startswith("Error") else "failed"
                    pipeline_log.log_tool_execution("query_recent_host_alerts", history_args, status, raw_result, tool_elapsed)
                    evidence = summarizer.summarize("query_recent_host_alerts", raw_result)
                    state.add_evidence(evidence)
                    execution_record = state.record_tool_execution("query_recent_host_alerts", history_args, status, evidence.content)
                    if execution_record:
                        current_audit.executions.append(execution_record)
                else:
                    pipeline_log.log_warning("Host alert history query blocked", policy.reason)

        # Baseline SIEM query on first loop: host + tight window around alert time
        if state.iteration_count == 1 and len(state.evidence) == 1:
            baseline_args = {
                "host_name": alert.entity.host.hostname if alert.entity.host else "",
                "alert_timestamp": alert.alert.timestamp.isoformat(),
                "window_back_minutes": 3,
                "window_forward_minutes": 3,
            }
            if baseline_args["host_name"]:
                pipeline_log.log_step("BASELINE_QUERY", "Running initial host/timeframe query (+/-3 minutes).")
                policy = policy_engine.check_tool_permission(state, "query_siem_host_logs", baseline_args)
                if policy.allowed:
                    tool_start = time.time()
                    raw_result = executor.execute("query_siem_host_logs", baseline_args)
                    tool_elapsed = time.time() - tool_start
                    status = "success" if not raw_result.startswith("Error") else "failed"
                    pipeline_log.log_tool_execution("query_siem_host_logs", baseline_args, status, raw_result, tool_elapsed)
                    evidence = summarizer.summarize("query_siem_host_logs", raw_result)
                    state.add_evidence(evidence)
                    execution_record = state.record_tool_execution("query_siem_host_logs", baseline_args, status, evidence.content)
                    if execution_record:
                        current_audit.executions.append(execution_record)
                else:
                    pipeline_log.log_warning("Baseline query blocked", policy.reason)
        
        # 7. Token Guard (disabled for external LLMs)
        
        # 8/9. Agent Intent -> Plan
        # Check Confidence first to see if we need more tools
        # Update deterministic risk score before confidence gating
        state.scoring_factors = build_risk_factors(state)
        state.risk_score = RiskScoringMatrix.calculate_score(state.scoring_factors)
        state.evidence_table = build_evidence_table(state.scoring_factors)
        risk_classification = RiskScoringMatrix.get_classification(state.risk_score)
        pipeline_log.log_step("RISK_SCORE", f"Risk Score: {state.risk_score:.1f} ({risk_classification})")

        pipeline_log.log_step("CONFIDENCE_CHECK", "Checking operational confidence...")
        op_conf_score = check_operational_confidence(state)
        op_conf_label = label_operational_confidence(op_conf_score)
        pipeline_log.log_step("CONFIDENCE_RESULT", f"Operational Confidence: {op_conf_score:.0f}% ({op_conf_label})")
        
        # Decide Phase
        state.current_phase = "investigation"
        if op_conf_score > 90 and is_conclusive_score(state.risk_score):
             pipeline_log.log_step("INVESTIGATION_COMPLETE", "Operational confidence >90% and risk score conclusive, proceeding to decision")
             break # Go to decision
        if op_conf_label == "medium":
             # Tier-2 Check
             pipeline_log.log_step("TIER2_ANALYSIS", "Medium confidence - running reasoning agent...")
             agent_start = pipeline_log.log_agent_start("ReasoningAgent", "Analyzing evidence for tier-2 confidence check")
             final_reasoning = reason_agent.analyze(state)
             pipeline_log.log_agent_end("ReasoningAgent", agent_start, final_reasoning[:200])
             
             # LLM discovery check for ReasonAgent
             update_ioc_store(state, final_reasoning, "ReasoningAgent")
             
             ana_conf = check_analytical_confidence(state, final_reasoning)
             pipeline_log.log_step("ANALYTICAL_CONFIDENCE", f"Analytical Confidence: {ana_conf}")
             
        # If Low, or Tier-2 sent us back:
        # Generate Intent
        pipeline_log.log_step("INTENT_GENERATION", "Generating investigation intent...")
        agent_start = pipeline_log.log_agent_start("InvestigationAgent", "Generating next investigation step")
        start_time = time.time()
        intent = inv_agent.generate_intent(state)
        elapsed = time.time() - start_time
        logger.info(f"Investigation Agent Intent took {elapsed:.2f}s")
        logger.info(f"Agent Intent: {intent}")
        pipeline_log.log_agent_end("InvestigationAgent", agent_start, intent)
        current_audit.intent = intent
        
        # LLM discovery check for InvestigationAgent
        update_ioc_store(state, intent, "InvestigationAgent")
        
        # Plan Tools
        pipeline_log.log_step("TOOL_PLANNING", "Planning tools based on intent...")
        plan_items = planner.plan_from_intent(intent, state)
        if not plan_items and state.iteration_count == 1:
             # Fallback: Use MITRE default plan if Agent is confused on step 1
             pipeline_log.log_step("FALLBACK_PLANNING", "No tools from intent, using MITRE-based fallback plan")
             plan_items = planner.plan_by_technique(techniques, state)
             
        if not plan_items:
             logger.warning("No tools planned. Retrying or escalating.")
             pipeline_log.log_warning("No tools planned for this intent", "Investigation may be stuck")
             current_audit.errors.append("No tools planned for this intent.")
             state.audit_trail.append(current_audit)
             # Stop early if we're stuck twice in a row.
             if len(state.audit_trail) >= 2:
                 last_two = state.audit_trail[-2:]
                 if all("No tools planned for this intent." in e for e in last_two for e in e.errors):
                     pipeline_log.log_warning("Stopping early due to repeated no-tool plans", "Investigation stuck")
                     break
             continue
             
        current_audit.tools_planned = [p['tool'] for p in plan_items]
        pipeline_log.log_data("PLANNED_TOOLS", [p['tool'] for p in plan_items])
             
        # Execute Tools
        pipeline_log.log_step("TOOL_EXECUTION", f"Executing {len(plan_items)} tool(s)...")
        for item in plan_items:
             tool = item['tool']
             args = item['args']
             
             # Policy Check
             policy = policy_engine.check_tool_permission(state, tool, args)
             if not policy.allowed:
                 logger.warning(f"Policy blocked {tool}: {policy.reason}")
                 pipeline_log.log_warning(f"Policy blocked {tool}", policy.reason)
                 state.record_tool_execution(tool, args, "denied_policy", policy.reason)
                 continue
                 
             # Execute
             logger.info(f"Executing {tool}...")
             tool_start = time.time()
             raw_result = executor.execute(tool, args)
             tool_elapsed = time.time() - tool_start
             
             status = "success"
             if raw_result.startswith("Error"):
                 status = "failed"
                 current_audit.errors.append(raw_result)
             
             # Log tool execution
             pipeline_log.log_tool_execution(tool, args, status, raw_result, tool_elapsed)
             
             # Summarize
             evidence = summarizer.summarize(tool, raw_result)
             state.add_evidence(evidence)
             
             # Record for deduplication & Audit
             execution_record = state.record_tool_execution(tool, args, status, evidence.content)
             if execution_record:
                 current_audit.executions.append(execution_record)
        
        state.audit_trail.append(current_audit)
             
    # --- Step 13: Final Decision ---
    pipeline_log.log_section("FINAL DECISION")
    logger.info("Generatng Final Decision...")
    agent_start = pipeline_log.log_agent_start("DecisionAgent", "Generating final verdict and recommendations")
    start_time = time.time()
    state.scoring_factors = build_risk_factors(state)
    state.risk_score = RiskScoringMatrix.calculate_score(state.scoring_factors)
    state.evidence_table = build_evidence_table(state.scoring_factors)
    final_classification = RiskScoringMatrix.get_classification(state.risk_score)
    final_output = decision_agent.decide(
        state,
        final_reasoning,
        scoring={
            "risk_score": state.risk_score,
            "classification": final_classification,
            "evidence_table": state.evidence_table,
        },
    )
    elapsed = time.time() - start_time
    logger.info(f"Decision Agent took {elapsed:.2f}s")
    pipeline_log.log_agent_end("DecisionAgent", agent_start, f"Classification: {final_output.get('classification', 'unknown')}")
    
    # --- Step 14: Output & Lifecycle (Memory Wipe) ---
    pipeline_log.log_step("FINAL_OUTPUT", f"Classification: {final_output.get('classification', 'unknown')}\n   Final Score: {final_output.get('final_score', 'unknown')}\n   Action: {final_output.get('action', 'unknown')}")
    print(json.dumps(final_output, indent=2))
    
    # --- Step 15: Export Audit Trail ---
    try:
        audit_filename = f"audit_trail_{alert.alert.id}.json"
        with open(audit_filename, "w") as f:
            # Convert state model to JSON
            audit_data = [a.model_dump() for a in state.audit_trail]
            json.dump(audit_data, f, indent=2, default=str)
        logger.info(f"Audit trail exported to {audit_filename}")
        pipeline_log.log_step("AUDIT_EXPORT", f"Audit trail exported to {audit_filename}")
    except Exception as e:
        logger.error(f"Failed to export audit trail: {e}")
        pipeline_log.log_error(str(e), "Failed to export audit trail")

    # --- Step 16: Send Email Notification ---
    pipeline_log.log_step("EMAIL_NOTIFICATION", "Sending triage report email...")
    
    email_notifier.send_triage_report(
        alert_data={
            "name": alert.alert.name,
            "severity": alert.alert.severity,
            "tags": alert.detection.mitre_techniques, # Corrected: 'detection' is a sibling of 'alert' in NormalizedSecurityAlert
            "description": alert.alert.description
        },
        triage_result=final_output,
        journal=final_output.get("journal", []),
        elapsed_time=time.time() - start_time, # start_time from Step 13
        ioc_list=state.ioc_store
    )
    
    # Close pipeline log
    pipeline_log.close()
    
    # WIPE MEMORY
    del state
    logger.info("Investigation State Wiped.")

if __name__ == "__main__":
    main()
