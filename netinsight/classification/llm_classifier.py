import json
import logging
import time

import requests
from django.conf import settings

logger = logging.getLogger("netinsight")

class LLMClassifier:
    def __init__(self):
        self.nvidia_api_key = getattr(settings, "NVIDIA_API_KEY", "")
        self.nvidia_model_name = getattr(settings, "NVIDIA_MODEL_NAME", "deepseek-ai/deepseek-r1")
        self.last_llm_latency_ms = 0
        self.last_llm_provider = "NVIDIA DeepSeek AI"
        self.last_llm_reasoning = ""

    def _get_system_prompt(self):
        return (
            "You are a network traffic classifier. You will be provided with packet features: "
            "packet_size, protocol, latency, packet_rate, conn_frequency. "
            "Analyze the features and return a JSON object with this exact schema: "
            '{"label": "Normal", "confidence": 0.95, "reasoning": "Standard web traffic"}'
        )

    def classify_packet(self, packet_dict):
        api_key = getattr(settings, "NVIDIA_API_KEY", None) or self.nvidia_api_key
        if not api_key:
            return None

        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.nvidia_api_key}",
            "Content-Type": "application/json"
        }

        features_str = json.dumps(packet_dict)

        payload = {
            "model": self.nvidia_model_name,
            "messages": [
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": f"Features: {features_str}"}
            ],
            "temperature": 0.1,
            "max_tokens": 128
        }

        start_time = time.time()
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=2.5)
            if response.status_code != 200 and payload["model"] != "meta/llama-3.1-70b-instruct":
                payload["model"] = "meta/llama-3.1-70b-instruct"
                response = requests.post(url, headers=headers, json=payload, timeout=2.5)

            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]

            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            result = json.loads(json_match.group(0)) if json_match else json.loads(content.strip())

            # Validate the model returned the documented schema before trusting it downstream.
            # Malformed/partial JSON from the model must not silently propagate as a "label".
            if not isinstance(result, dict) or not isinstance(result.get("label"), str) or not result["label"]:
                logger.error(f"NVIDIA API returned malformed classification payload: {result!r}")
                return None

            self.last_llm_latency_ms = (time.time() - start_time) * 1000
            self.last_llm_reasoning = result.get("reasoning", "")

            return result
        except Exception as e:
            logger.error(f"NVIDIA API Error: {e}")
            return None

    def classify_batch(self, features_df):
        start_time = time.time()

        labels = []
        confs = []
        reasonings = []

        for _, row in features_df.iterrows():
            features_dict = {
                "packet_size": row.get("packet_size", 0),
                "protocol": row.get("protocol", 0),
                "latency": row.get("latency", 0),
                "packet_rate": row.get("packet_rate", 0),
                "conn_frequency": row.get("conn_frequency", 0)
            }

            result = self.classify_packet(features_dict)

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
            "provider": self.last_llm_provider,
            "model": self.nvidia_model_name
        }
