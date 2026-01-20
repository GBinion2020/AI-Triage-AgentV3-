import os
import requests
import json
import logging

logger = logging.getLogger("EnterpriseSOC.LLM")

class LLMClient:
    """
    Unified LLM Client supporting Local (Ollama) and External (OpenAI-compatible) providers.
    """
    def __init__(self, mode="local", model=None):
        self.mode = mode.lower()
        
        if self.mode == "local":
            self.model = model or os.getenv("LLM_MODEL", "llama3.1:8b")
            self.url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/api/generate")
            logger.info(f"LLM Client initialized in LOCAL mode (Model: {self.model})")
        else:
            self.model = model or os.getenv("EXTERNAL_LLM_MODEL")
            self.url = os.getenv("EXTERNAL_LLM_URL")
            self.api_key = os.getenv("EXTERNAL_LLM_API_KEY")
            
            if not all([self.model, self.url, self.api_key]):
                logger.error("External LLM configuration missing in .env")
                raise ValueError("External LLM configuration (URL, Model, API Key) is required for external mode.")
            
            logger.info(f"LLM Client initialized in EXTERNAL mode (Model: {self.model})")

    def generate(self, prompt: str) -> str:
        """
        Generates a response from the configured LLM provider.
        """
        try:
            if self.mode == "local":
                return self._generate_local(prompt)
            else:
                return self._generate_external(prompt)
        except Exception as e:
            logger.error(f"LLM Generation Error ({self.mode}): {e}")
            raise

    def _generate_local(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        response = requests.post(self.url, json=payload, timeout=1000)
        response.raise_for_status()
        return response.json().get("response", "").strip()

    def _generate_external(self, prompt: str) -> str:
        """
        Standard OpenAI-compatible Chat Completion API call.
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        
        # Note: External APIs usually have shorter timeouts than local ones
        response = requests.post(self.url, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
        
        data = response.json()
        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"].strip()
        
        raise ValueError(f"Unexpected response format from external LLM: {data}")
