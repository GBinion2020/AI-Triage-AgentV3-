from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field
from schemas.alert import NormalizedSecurityAlert

class EvidenceType(str, Enum):
    LOG = "log"
    IOC = "ioc"
    CONTEXT = "context"
    ERROR = "error"

class Evidence(BaseModel):
    """ Technical fact gathered by a tool. """
    content: str = Field(..., description="Raw output from the tool (for audit)")
    summary: str = Field(..., description="Concise technical summary (for LLM context)")
    source_tool: str
    timestamp: datetime = Field(default_factory=datetime.now)
    type: EvidenceType = EvidenceType.LOG
    confidence: float = 1.0
    
class Hypothesis(BaseModel):
    """ A working theory about the alert. """
    description: str = Field(..., description="The hypothesis")
    status: str = Field("active", description="active, proven, disproven")
    supporting_evidence_indices: List[int] = Field(default_factory=list, description="Indices of evidence in the state that support this")

class ToolExecutionRecord(BaseModel):
    """ Record of a tool execution for effective deduplication. """
    tool_name: str
    arguments: Dict[str, Any]
    query_hash: str = Field(..., description="Hash of the tool+args to check for duplicates")
    status: str = Field("success", description="success, failed, skipped_duplicate, denied_policy")
    timestamp: datetime = Field(default_factory=datetime.now)
    result_summary: Optional[str] = None

class LoopAudit(BaseModel):
    """ Technical audit of a single investigation loop. """
    iteration: int
    intent: str
    tools_planned: List[str]
    executions: List[ToolExecutionRecord] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

class InvestigationState(BaseModel):
    """
    Step 11 Object: The living case memory.
    This is strict ephemeral memory that gets WIPED after decision.
    """
    alert: NormalizedSecurityAlert
    
    # The Knowledge
    evidence: List[Evidence] = Field(default_factory=list)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    
    # The History & Audit
    tool_history: List[ToolExecutionRecord] = Field(default_factory=list)
    audit_trail: List[LoopAudit] = Field(default_factory=list)
    query_hashes: List[str] = Field(default_factory=list, description="Set of hashes for queries deemed 'DONE'")
    
    # Metadata
    start_time: datetime = Field(default_factory=datetime.now)
    iteration_count: int = Field(0)
    current_phase: str = Field("intake", description="intake, investigation, reasoning, decision")
    
    def add_evidence(self, ev: Evidence):
        self.evidence.append(ev)
        
    def record_tool_execution(self, tool: str, args: Dict, status: str, result: str = ""):
        # Create a deterministic hash of tool+args for dedup
        import json
        import hashlib
        # Sort keys to ensure consistent hash
        arg_str = json.dumps(args, sort_keys=True, default=str)
        q_hash = hashlib.md5(f"{tool}:{arg_str}".encode()).hexdigest()
        
        record = ToolExecutionRecord(
            tool_name=tool,
            arguments=args,
            query_hash=q_hash,
            status=status,
            result_summary=result
        )
        self.tool_history.append(record)
        
        if status == "success":
            self.query_hashes.append(q_hash)
            
        return record
            
    def is_duplicate(self, tool: str, args: Dict) -> bool:
        import json
        import hashlib
        arg_str = json.dumps(args, sort_keys=True, default=str)
        q_hash = hashlib.md5(f"{tool}:{arg_str}".encode()).hexdigest()
        return q_hash in self.query_hashes
