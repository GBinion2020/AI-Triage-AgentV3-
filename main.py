import os
import sys
import logging
import json
import time
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
from core.confidence import check_operational_confidence, check_analytical_confidence
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
        
    # --- Step 2b: Intake Agent ---
    agent_start = pipeline_log.log_agent_start("IntakeAgent", "Evaluating alert for initial triage")
    start_time = time.time()
    intake_decision = intake_agent.evaluate(alert)
    elapsed = time.time() - start_time
    logger.info(f"Intake Agent took {elapsed:.2f}s")
    pipeline_log.log_agent_end("IntakeAgent", agent_start, f"Decision: {intake_decision}")
    
    if intake_decision == "close_benign":
        logger.info("Alert closed by Intake Agent as Benign.")
        pipeline_log.log_step("ALERT_CLOSED", "Alert closed by Intake Agent as benign")
        pipeline_log.close()
        return # Done
        
    # --- Step 3: Build Context ---
    pipeline_log.log_step("CONTEXT_BUILD", "Building initial investigation state...")
    state = build_initial_state(alert)
    pipeline_log.log_step("CONTEXT_BUILD_COMPLETE", "Investigation state initialized")
    
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
        
        # 7. Token Guard
        if not token_guard.check_budget(state):
             logger.warning("Token budget exceeded. Pruning...")
             pipeline_log.log_warning("Token budget exceeded, pruning state...")
             state = token_guard.prune(state)
        
        # 8/9. Agent Intent -> Plan
        # Check Confidence first to see if we need more tools
        pipeline_log.log_step("CONFIDENCE_CHECK", "Checking operational confidence...")
        op_conf = check_operational_confidence(state)
        pipeline_log.log_step("CONFIDENCE_RESULT", f"Operational Confidence: {op_conf}")
        
        # Decide Phase
        state.current_phase = "investigation"
        if op_conf == "medium":
             # Tier-2 Check
             pipeline_log.log_step("TIER2_ANALYSIS", "Medium confidence - running reasoning agent...")
             agent_start = pipeline_log.log_agent_start("ReasoningAgent", "Analyzing evidence for tier-2 confidence check")
             final_reasoning = reason_agent.analyze(state)
             pipeline_log.log_agent_end("ReasoningAgent", agent_start, final_reasoning[:200])
             
             ana_conf = check_analytical_confidence(state, final_reasoning)
             pipeline_log.log_step("ANALYTICAL_CONFIDENCE", f"Analytical Confidence: {ana_conf}")
             if ana_conf == "high":
                 pipeline_log.log_step("INVESTIGATION_COMPLETE", "High analytical confidence achieved, proceeding to decision")
                 break # Go to decision
        elif op_conf == "high":
             pipeline_log.log_step("INVESTIGATION_COMPLETE", "High operational confidence achieved, proceeding to decision")
             break # Go to decision
             
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
    final_output = decision_agent.decide(state, final_reasoning)
    elapsed = time.time() - start_time
    logger.info(f"Decision Agent took {elapsed:.2f}s")
    pipeline_log.log_agent_end("DecisionAgent", agent_start, f"Classification: {final_output.get('classification', 'unknown')}")
    
    # --- Step 14: Output & Lifecycle (Memory Wipe) ---
    pipeline_log.log_step("FINAL_OUTPUT", f"Classification: {final_output.get('classification', 'unknown')}\n   Confidence: {final_output.get('confidence_score', 'unknown')}\n   Action: {final_output.get('action', 'unknown')}")
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
        elapsed_time=time.time() - start_time # start_time from Step 13
    )
    
    # Close pipeline log
    pipeline_log.close()
    
    # WIPE MEMORY
    del state
    logger.info("Investigation State Wiped.")

if __name__ == "__main__":
    main()
