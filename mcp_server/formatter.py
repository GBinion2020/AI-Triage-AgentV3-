from typing import Any, Dict
import json

def normalize_tool_output(tool_name: str, raw_result: Any) -> str:
    """
    Wraps raw tool output in a consistent schema-aligned structure.
    This helps agents understand depth and entity relationships.
    """
    
    # If it's already an error string, just return it
    if isinstance(raw_result, str) and raw_result.startswith("Error"):
        return raw_result

    # Base structure
    normalized = {
        "tool_metadata": {
            "name": tool_name,
            "interpretation": "technical_evidence"
        },
        "extracted_entities": {},
        "raw_data_summary": None
    }

    try:
        # If it's a string that looks like JSON, parse it
        if isinstance(raw_result, str):
            try:
                data = json.loads(raw_result)
            except:
                data = {"content": raw_result}
        else:
            data = raw_result

        # Tool-specific mapping
        if tool_name == "query_siem_host_logs":
            normalized["extracted_entities"]["process_events"] = data
            normalized["raw_data_summary"] = f"Gathered {len(data) if isinstance(data, list) else 1} process/log entries."
        
        elif tool_name == "check_virustotal":
            normalized["extracted_entities"]["reputation"] = data
            normalized["raw_data_summary"] = "Reputation analysis retrieved."

        elif tool_name == "search_entra_logs":
            normalized["extracted_entities"]["identity_events"] = data
            normalized["raw_data_summary"] = "Identity/Auth logs retrieved."

        else:
            normalized["data"] = data
            normalized["raw_data_summary"] = "Standard tool output retrieved."

        return json.dumps(normalized, indent=2)

    except Exception as e:
        return f"Normalization Error: {str(e)}\nRaw: {str(raw_result)[:500]}"
