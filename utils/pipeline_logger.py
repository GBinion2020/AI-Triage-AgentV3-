import os
import sys
from datetime import datetime
from typing import Optional, Any, Dict
from contextlib import contextmanager
import threading

class PipelineLogger:
    """
    Comprehensive pipeline logger that outputs to both CLI and file.
    Provides step-by-step visibility into the SOC agent pipeline execution.
    """
    
    def __init__(self, alert_id: str, log_dir: str = "pipeline_logs"):
        """
        Initialize pipeline logger for a specific alert.
        
        Args:
            alert_id: The alert ID being processed
            log_dir: Directory to store log files
        """
        self.alert_id = alert_id
        self.log_dir = log_dir
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Create log file with timestamp
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(log_dir, f"pipeline_{alert_id}_{timestamp}.log")
        
        # Initialize log file
        self._write_header()
    
    def _write_header(self):
        """Write log file header"""
        header = f"""
{'='*80}
SOC AI TRIAGE AGENT - PIPELINE LOG
{'='*80}
Alert ID: {self.alert_id}
Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}

"""
        self._write_to_file(header)
        self._write_to_cli(header)
    
    def _write_to_file(self, message: str):
        """Write message to log file"""
        with self.lock:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(message)
            except Exception as e:
                print(f"[LOGGER ERROR] Failed to write to log file: {e}")
    
    def _write_to_cli(self, message: str):
        """Write message to CLI"""
        print(message, end='')
        sys.stdout.flush()
    
    def _get_timestamp(self) -> str:
        """Get current timestamp relative to start"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return f"[+{elapsed:>7.2f}s]"
    
    def log_step(self, step_name: str, description: str, level: str = "INFO"):
        """
        Log a pipeline step.
        
        Args:
            step_name: Name of the step (e.g., "ALERT_INGESTION", "TOOL_EXECUTION")
            description: Description of what's happening
            level: Log level (INFO, WARNING, ERROR)
        """
        timestamp = self._get_timestamp()
        
        # Format based on level
        if level == "ERROR":
            prefix = "[ERROR]"
            separator = "!" * 60
        elif level == "WARNING":
            prefix = "[WARN]"
            separator = "-" * 60
        else:
            prefix = "[INFO]"
            separator = "-" * 60
        
        message = f"\n{timestamp} {prefix} [{step_name}]\n{description}\n"
        
        self._write_to_file(message)
        self._write_to_cli(message)
    
    def log_section(self, section_name: str):
        """
        Log a major section separator.
        
        Args:
            section_name: Name of the section
        """
        timestamp = self._get_timestamp()
        separator = "=" * 80
        message = f"\n{separator}\n{timestamp} [SECTION] {section_name}\n{separator}\n"
        
        self._write_to_file(message)
        self._write_to_cli(message)
    
    def log_iteration(self, iteration: int, max_iterations: int):
        """
        Log the start of an investigation iteration.
        
        Args:
            iteration: Current iteration number
            max_iterations: Maximum iterations allowed
        """
        self.log_section(f"ITERATION {iteration}/{max_iterations}")
    
    def log_agent_start(self, agent_name: str, context: str = ""):
        """
        Log the start of an agent's execution.
        
        Args:
            agent_name: Name of the agent
            context: Additional context about what the agent will do
        """
        timestamp = self._get_timestamp()
        message = f"\n{timestamp} [AGENT] [{agent_name}] Starting...\n"
        if context:
            message += f"   Context: {context}\n"
        
        self._write_to_file(message)
        self._write_to_cli(message)
        
        return datetime.now()  # Return start time for timing
    
    def log_agent_end(self, agent_name: str, start_time: datetime, result: str = ""):
        """
        Log the end of an agent's execution with timing.
        
        Args:
            agent_name: Name of the agent
            start_time: When the agent started
            result: Summary of the agent's output
        """
        elapsed = (datetime.now() - start_time).total_seconds()
        timestamp = self._get_timestamp()
        
        message = f"{timestamp} [DONE] [{agent_name}] Completed in {elapsed:.2f}s\n"
        if result:
            # Truncate if too long
            result_display = result[:200] + "..." if len(result) > 200 else result
            message += f"   Result: {result_display}\n"
        
        self._write_to_file(message)
        self._write_to_cli(message)
    
    def log_tool_execution(self, tool_name: str, args: Dict[str, Any], status: str, result: str = "", execution_time: float = 0.0):
        """
        Log a tool execution with inputs and outputs.
        
        Args:
            tool_name: Name of the tool
            args: Tool arguments (will be sanitized)
            status: Execution status (success, failed, denied)
            result: Tool output (will be truncated if too long)
            execution_time: Time taken to execute
        """
        timestamp = self._get_timestamp()
        
        # Status indicator
        status_indicator = {
            "success": "[OK]",
            "failed": "[FAIL]",
            "denied": "[DENY]"
        }.get(status, "[?]")
        
        # Sanitize args (remove sensitive data, truncate long values)
        sanitized_args = {}
        for key, value in args.items():
            if isinstance(value, str) and len(value) > 100:
                sanitized_args[key] = value[:100] + "..."
            else:
                sanitized_args[key] = value
        
        message = f"\n{timestamp} [TOOL] [{tool_name}] {status_indicator} {status.upper()}\n"
        message += f"   Arguments: {sanitized_args}\n"
        
        if execution_time > 0:
            message += f"   Execution Time: {execution_time:.2f}s\n"
        
        if result:
            # Truncate result if too long
            result_display = result[:300] + "..." if len(result) > 300 else result
            message += f"   Result: {result_display}\n"
        
        self._write_to_file(message)
        self._write_to_cli(message)
    
    def log_llm_call(self, agent_name: str, prompt_length: int, response_length: int, execution_time: float):
        """
        Log an LLM API call.
        
        Args:
            agent_name: Name of the agent making the call
            prompt_length: Length of the prompt in characters
            response_length: Length of the response in characters
            execution_time: Time taken for the LLM call
        """
        timestamp = self._get_timestamp()
        message = f"{timestamp} [LLM] {agent_name} - Prompt: {prompt_length} chars, Response: {response_length} chars, Time: {execution_time:.2f}s\n"
        
        self._write_to_file(message)
        self._write_to_cli(message)
    
    def log_error(self, error_message: str, context: str = ""):
        """
        Log an error with highlighting.
        
        Args:
            error_message: The error message
            context: Additional context about where the error occurred
        """
        self.log_step("ERROR", f"{context}\n   Error: {error_message}", level="ERROR")
    
    def log_warning(self, warning_message: str, context: str = ""):
        """
        Log a warning.
        
        Args:
            warning_message: The warning message
            context: Additional context
        """
        self.log_step("WARNING", f"{context}\n   Warning: {warning_message}", level="WARNING")
    
    def log_data(self, label: str, data: Any, truncate: int = 500):
        """
        Log structured data (dict, list, etc.).
        
        Args:
            label: Label for the data
            data: The data to log
            truncate: Maximum length before truncation
        """
        timestamp = self._get_timestamp()
        data_str = str(data)
        
        if len(data_str) > truncate:
            data_str = data_str[:truncate] + f"... (truncated, total length: {len(str(data))})"
        
        message = f"{timestamp} [DATA] [{label}]\n   {data_str}\n"
        
        self._write_to_file(message)
        self._write_to_cli(message)
    
    @contextmanager
    def agent_context(self, agent_name: str, context: str = ""):
        """
        Context manager for automatic agent timing.
        
        Usage:
            with pipeline_log.agent_context("IntakeAgent", "Evaluating alert"):
                result = intake_agent.evaluate(alert)
        
        Args:
            agent_name: Name of the agent
            context: Additional context
        """
        start_time = self.log_agent_start(agent_name, context)
        result_holder = {"result": None}
        
        try:
            yield result_holder
        except Exception as e:
            self.log_error(str(e), f"Exception in {agent_name}")
            raise
        finally:
            # Log completion even if there was an exception
            result = result_holder.get("result", "")
            self.log_agent_end(agent_name, start_time, str(result) if result else "")
    
    def close(self):
        """Close the logger and write footer"""
        end_time = datetime.now()
        total_time = (end_time - self.start_time).total_seconds()
        
        footer = f"""
{'='*80}
Pipeline execution completed
Total Time: {total_time:.2f}s
Ended: {end_time.strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}
"""
        self._write_to_file(footer)
        self._write_to_cli(footer)
