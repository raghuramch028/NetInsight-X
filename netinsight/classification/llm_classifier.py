import json
import logging
import time

import requests
from django.conf import settings

logger = logging.getLogger("netinsight")

class LLMClassifier:
    def __init__(self):
        self.provider = getattr(settings, "NETINSIGHT_LLM_PROVIDER", "nvidia")
        self.nvidia_api_key = getattr(settings, "NVIDIA_API_KEY", "")
        self.nvidia_model_name = getattr(settings, "NVIDIA_MODEL_NAME", "meta/llama-3.1-70b-instruct")
        self.gemini_api_key = getattr(settings, "GEMINI_API_KEY", "")
        self.gemini_model_name = getattr(settings, "GEMINI_MODEL_NAME", "gemini-1.5-flash")

    def _get_system_prompt(self):
        return (
            "You are a network traffic classifier. You will be provided with packet features: "
            "packet_size, protocol, latency, packet_rate, conn_frequency. "
            "Analyze the features and return a JSON object with this exact schema: "
            '{"label": "Normal", "confidence": 0.95, "reasoning": "Standard TCP web traffic pattern"}'
        )

    def _call_nvidia(self, features_str):
        if not self.nvidia_api_key:
            return None

        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.nvidia_api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.nvidia_model_name,
            "messages": [
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": f"Features: {features_str}"}
            ],
            "temperature": 0.1,
            "max_tokens": 128
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=5)
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]

            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]

            return json.loads(content.strip())
        except Exception as e:
            logger.error(f"NVIDIA API Error: {e}")
            return None

    def _call_gemini(self, features_str):
        if not self.gemini_api_key:
            return None

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model_name}:generateContent?key={self.gemini_api_key}"
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "system_instruction": {
                "parts": [{"text": self._get_system_prompt()}]
            },
            "contents": [{
                "parts": [{"text": f"Features: {features_str}"}]
            }],
            "generationConfig": {
                "temperature": 0.1
            }
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=5)
            response.raise_for_status()
            data = response.json()
            content = data["candidates"][0]["content"]["parts"][0]["text"]

            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]

            return json.loads(content.strip())
        except Exception as e:
            logger.error(f"Gemini API Error: {e}")
            return None

    def classify_batch(self, features_df):
        start_time = time.time()

        labels = []
        confs = []
        reasonings = []

        api_available = True
        if self.provider == "nvidia" and not self.nvidia_api_key or self.provider == "gemini" and not self.gemini_api_key:
            api_available = False

        if not api_available:
            return None

        for _, row in features_df.iterrows():
            features_dict = {
                "packet_size": row.get("packet_size", 0),
                "protocol": row.get("protocol", 0),
                "latency": row.get("latency", 0),
                "packet_rate": row.get("packet_rate", 0),
                "conn_frequency": row.get("conn_frequency", 0)
            }
            features_str = json.dumps(features_dict)

            result = None
            if self.provider == "nvidia":
                result = self._call_nvidia(features_str)
            elif self.provider == "gemini":
                result = self._call_gemini(features_str)

            if result:
                labels.append(result.get("label", "Unknown"))
                confs.append(result.get("confidence", 0.0))
                reasonings.append(result.get("reasoning", ""))
            else:
                return None

        latency_ms = (time.time() - start_time) * 1000

        return {
            "predictions": labels,
            "confidence": confs,
            "reasoning": reasonings,
            "latency_ms": latency_ms,
            "provider": self.provider,
            "model": self.nvidia_model_name if self.provider == "nvidia" else self.gemini_model_name
        }
