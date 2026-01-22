import os
import json
import secrets
from datetime import datetime
from fastapi import FastAPI, Request, Header, HTTPException

app = FastAPI(title="SOC Feedback Ingestion")

API_KEY = os.getenv("FEEDBACK_API_KEY")
if not API_KEY:
    API_KEY = secrets.token_urlsafe(32)
    print("FEEDBACK_API_KEY not set. Generated temporary key:")
    print(API_KEY)
    print("Set FEEDBACK_API_KEY in .env to make it persistent.")


def _require_api_key(x_api_key: str | None) -> None:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/webhook/jira")
async def jira_webhook(request: Request, x_api_key: str | None = Header(default=None)):
    _require_api_key(x_api_key)
    payload = await request.json()
    print("=== JIRA WEBHOOK PAYLOAD START ===")
    print(json.dumps(payload, indent=2))
    print("=== JIRA WEBHOOK PAYLOAD END ===")
    return {"status": "received", "received_at": datetime.utcnow().isoformat() + "Z"}
