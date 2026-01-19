from typing import Dict, Any
from schemas.state import ToolExecutionRecord
from mcp_server.tools import siem, virustotal, entra, cloudtrail, sandbox
from mcp_server.formatter import normalize_tool_output

class ToolExecutor:
    """
    Step 9: Executor.
    Calls the "MCP" tools (imported largely directly for now).
    """
    
    def execute(self, tool_name: str, args: Dict[str, Any]) -> str:
        """
        Executes the tool and returns the normalized string output.
        """
        try:
            raw_result = ""
            if tool_name == "query_siem_host_logs":
                raw_result = siem.query_host_logs(**args)
            elif tool_name == "check_virustotal":
                raw_result = virustotal.lookup_indicator(**args)
            elif tool_name == "search_entra_logs":
                raw_result = entra.search_entra_logs(**args)
            elif tool_name == "search_cloudtrail":
                raw_result = cloudtrail.search_cloudtrail(**args)
            elif tool_name == "submit_sandbox":
                raw_result = sandbox.submit_file_sandbox(**args)
            else:
                return f"Error: Unknown tool '{tool_name}'"
                
            return normalize_tool_output(tool_name, raw_result)

        except Exception as e:
            return f"Error executing {tool_name}: {str(e)}"
