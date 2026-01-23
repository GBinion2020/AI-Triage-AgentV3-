import os
import json
import secrets
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Request, Header, HTTPException, Query
from schemas.feedback import NormalizedJiraFeedback
from feedback_api.db import save_feedback

app = FastAPI(title="SOC Feedback Ingestion")

def _load_api_key() -> str:
    env_key = os.getenv("FEEDBACK_API_KEY")
    if env_key:
        return env_key.strip()

    env_path = Path(__file__).resolve().parents[1] / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("FEEDBACK_API_KEY="):
                return line.split("=", 1)[1].strip()

    return secrets.token_urlsafe(32)


API_KEY = _load_api_key()
if "FEEDBACK_API_KEY" not in os.environ:
    print("FEEDBACK_API_KEY not set in environment. Using key loaded from .env or generated.")


def _require_api_key(x_api_key: str | None) -> None:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

def _safe_get(mapping: dict, keys: list, default=None):
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current

def _normalize_jira_payload(payload: dict) -> dict:
    fields = payload.get("fields", {}) if isinstance(payload, dict) else {}
    return {
        "source": "jira",
        "received_at": datetime.utcnow().isoformat() + "Z",
        "issue": {
            "id": payload.get("id"),
            "key": payload.get("key"),
            "summary": _safe_get(fields, ["summary"]),
            "updated": _safe_get(fields, ["updated"]),
            "status": _safe_get(fields, ["status", "name"]),
            "project_key": _safe_get(fields, ["project", "key"]),
            "project_name": _safe_get(fields, ["project", "name"]),
        },
        "triage": {
            "description": _safe_get(fields, ["description"]),
            "close_note": _safe_get(fields, ["customfield_10101"]),
            "detection_classification": _safe_get(fields, ["customfield_10100", "value"]),
            "triage_verdict": _safe_get(fields, ["customfield_10099", "value"]),
        },
    }

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/webhook/jira")
async def jira_webhook(
    request: Request,
    x_api_key: str | None = Header(default=None),
    debug: bool = Query(default=False),
):
    _require_api_key(x_api_key)
    try:
        payload = await request.json()
    except Exception as e:
        print(f"Failed to parse Jira payload JSON: {e}")
        return {"status": "error", "error": "invalid_json"}

    print("=== JIRA WEBHOOK PAYLOAD START ===")
    print(json.dumps(payload, indent=2))
    print("=== JIRA WEBHOOK PAYLOAD END ===")

    try:
        normalized_dict = _normalize_jira_payload(payload)
        normalized = NormalizedJiraFeedback.model_validate(normalized_dict)
    except Exception as e:
        print(f"Failed to normalize Jira payload: {e}")
        return {"status": "error", "error": "normalization_failed"}

    print("=== JIRA WEBHOOK NORMALIZED START ===")
    print(json.dumps(normalized.model_dump(), indent=2))
    print("=== JIRA WEBHOOK NORMALIZED END ===")
    try:
        save_feedback(payload, normalized.model_dump())
    except Exception as e:
        print(f"Feedback DB insert failed: {e}")
    response = {"status": "received", "received_at": datetime.utcnow().isoformat() + "Z"}
    if debug:
        response["normalized"] = normalized.model_dump()
    return response
