from typing import Optional, Union
from pydantic import BaseModel, Field


class JiraIssueFeedback(BaseModel):
    id: Optional[int] = Field(None, description="Jira issue ID")
    key: Optional[str] = Field(None, description="Jira issue key, e.g. SOC-28")
    summary: Optional[str] = None
    updated: Optional[Union[int, str]] = None
    status: Optional[str] = None
    project_key: Optional[str] = None
    project_name: Optional[str] = None


class JiraTriageFeedback(BaseModel):
    description: Optional[str] = None
    close_note: Optional[str] = None
    detection_classification: Optional[str] = None
    triage_verdict: Optional[str] = None


class NormalizedJiraFeedback(BaseModel):
    source: str = "jira"
    received_at: str
    issue: JiraIssueFeedback
    triage: JiraTriageFeedback
