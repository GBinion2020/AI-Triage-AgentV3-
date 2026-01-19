from typing import List, Dict, Optional
from pydantic import BaseModel, Field

class PolicyConfiguration(BaseModel):
    """
    Step 6 Configuration: Organizational rules.
    """
    max_steps: int = 15
    max_tokens_total: int = 50000
    
    # Tool Allow/Block lists
    allowed_tools: List[str] = Field(default_factory=list, description="Explicitly allowed tools")
    forbidden_tools: List[str] = Field(default_factory=list, description="Explicitly forbidden tools (e.g. active_response)")
    
    # Sensitive scopes
    sensitive_users: List[str] = Field(default_factory=list, description="Users requiring higher confident threshold")
    critical_hosts: List[str] = Field(default_factory=list, description="Hosts requiring manual approval")

class PolicyDecision(BaseModel):
    """
    Output of the Policy Engine for a specific step.
    """
    allowed: bool = True
    reason: str = ""
    forced_tools: List[str] = Field(default_factory=list, description="Tools that MUST be run (e.g. Policy mandates checking VT for Hash)")
    blocked_tools: List[str] = Field(default_factory=list)
    max_depth_override: Optional[int] = None
