import requests
import json


class LLMClient:
    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        self.url = "http://localhost:11434/api/generate"

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }

        response = requests.post(
            self.url,
            json=payload,
            timeout=1000
        )

        response.raise_for_status()
        data = response.json()

        return data.get("response", "").strip()
