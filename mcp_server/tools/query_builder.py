from typing import List, Dict, Any, Union
import json
import os
import sys

# Ensure we can import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from elastic.client import ElasticClient

# Configuration
WHITELISTED_FIELDS = [
    "event.kind", "event.category", "event.type", "event.action", "event.dataset",
    "host.name", "user.name", "process.name", "process.pid",
    "source.ip", "destination.ip"
]

def build_siem_query(filters: List[Dict[str, str]]) -> str:
    """
    Dynamically constructs and executes an Elasticsearch query against 'logs-*'.
    
    Instructions for LLM:
    - Each filter in the 'filters' list should be a dictionary with:
        - 'field': One of the allowed ECS fields (see below).
        - 'value': The value to search for.
        - 'logic': One of ['AND', 'OR', 'NOT'].
    
    Allowed Fields:
    - event.*: kind, category, type, action, dataset
    - host.name
    - user.name
    - process.*: name, pid
    - source.ip, destination.ip
    
    Example input:
    filters = [
        {"field": "host.name", "value": "workstation-01", "logic": "AND"},
        {"field": "process.name", "value": "powershell.exe", "logic": "AND"},
        {"field": "user.name", "value": "admin", "logic": "NOT"}
    ]
    """
    client = ElasticClient()
    
    must_clauses = []
    must_not_clauses = []
    should_clauses = []
    
    for f in filters:
        field = f.get("field")
        value = f.get("value")
        logic = f.get("logic", "AND").upper()
        
        if field not in WHITELISTED_FIELDS:
            return f"Error: Field '{field}' is not in the whitelisted fields: {WHITELISTED_FIELDS}"
            
        clause = {"match": {field: value}}
        
        if logic == "AND":
            must_clauses.append(clause)
        elif logic == "NOT":
            must_not_clauses.append(clause)
        elif logic == "OR":
            should_clauses.append(clause)
        else:
            return f"Error: Unsupported logic operator '{logic}'. Use AND, OR, or NOT."

    dsl = {
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": must_clauses,
                "must_not": must_not_clauses,
                "should": should_clauses,
                "minimum_should_match": 1 if should_clauses else 0
            }
        }
    }
    
    try:
        response = client.post("/logs-*/_search", payload=dsl)
        hits = response.get("hits", {}).get("hits", [])
        
        if not hits:
            return f"No logs found matching the criteria in logs-*."
            
        # Simplified summary for LLM
        summary = []
        for h in hits:
            s = h["_source"]
            ts = s.get("@timestamp")
            action = s.get("event", {}).get("action", "unknown")
            msg = s.get("message", "No message")
            summary.append(f"[{ts}] {action}: {msg}")
            
        return f"Found {len(hits)} matching logs:\n" + "\n".join(summary[:20])
        
    except Exception as e:
        return f"Error executing built query: {str(e)}"
