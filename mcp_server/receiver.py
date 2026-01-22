from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import sys
import os

# Ensure we can import the ingestion tool
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mcp_server.tools.feedback import ingest_feedback

app = FastAPI(title="SOC Analyst Feedback Receiver")

class JiraFeedback(BaseModel):
    alert_id: str
    notes: str
    verdict: str
    artifacts: Optional[List[str]] = []
    secret_token: Optional[str] = None

@app.post("/ingest/feedback")
async def handle_jira_feedback(feedback: JiraFeedback):
    """
    Endpoint for Jira Automations to send POST requests when a ticket is resolved.
    """
    # Simple token validation if configured (placeholder for security)
    # expected_token = os.getenv("JIRA_WEBHOOK_SECRET")
    # if expected_token and feedback.secret_token != expected_token:
    #     raise HTTPException(status_code=403, detail="Invalid secret token")

    print(f"Received feedback for {feedback.alert_id}")
    
    result = ingest_feedback(
        alert_id=feedback.alert_id,
        analyst_notes=feedback.notes,
        verdict=feedback.verdict,
        artifacts=feedback.artifacts
    )
    
    if "Error" in result:
        raise HTTPException(status_code=500, detail=result)
        
    return {"status": "success", "message": result}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    # Use environment variables for host/port if needed, fallback to defaults
    host = os.getenv("FEEDBACK_RECEIVER_HOST", "0.0.0.0")
    port = int(os.getenv("FEEDBACK_RECEIVER_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)
