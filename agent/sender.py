import os
import time
import requests
from agent.logger import logger
from agent import config

class TelemetrySender:
    """Handles communications with the central Django API. Implements backoff retries."""

    def __init__(self):
        self.agent_id = self.load_agent_id()

    def load_agent_id(self) -> str | None:
        """Retrieves persistent agent ID from disk if available."""
        if os.path.exists(config.AGENT_ID_FILE):
            try:
                with open(config.AGENT_ID_FILE, encoding="utf-8") as f:
                    agent_id = f.read().strip()
                    if agent_id:
                        logger.info(f"Loaded existing Agent ID: {agent_id}")
                        return agent_id
            except Exception as e:
                logger.error(f"Failed to read agent ID file: {e}")
        return None

    def save_agent_id(self, agent_id: str) -> None:
        """Persists the assigned Agent ID UUID to disk."""
        try:
            with open(config.AGENT_ID_FILE, "w", encoding="utf-8") as f:
                f.write(agent_id)
            self.agent_id = agent_id
            logger.info(f"Saved assigned Agent ID to disk: {agent_id}")
        except Exception as e:
            logger.error(f"Failed to write agent ID file: {e}")

    def register(self, mac_address: str, hostname: str, device_type: str, vendor: str) -> bool:
        """Registers the agent on Laptop 1 server, retrying with backoff if unreachable."""
        payload = {
            "mac_address": mac_address,
            "hostname": hostname,
            "device_type": device_type,
            "vendor": vendor
        }

        backoff = 5.0
        max_backoff = 60.0

        while True:
            logger.info(f"Attempting to register agent at {config.REGISTRATION_ENDPOINT}...")
            try:
                response = requests.post(config.REGISTRATION_ENDPOINT, json=payload, timeout=10.0)
                if response.status_code == 200 or response.status_code == 201:
                    data = response.json()
                    agent_id = data.get("agent_id")
                    if agent_id:
                        self.save_agent_id(agent_id)
                        logger.info("Agent registration successful.")
                        return True
                    else:
                        logger.error("Registration response did not contain 'agent_id'.")
                else:
                    logger.error(f"Server rejected registration (Status: {response.status_code}): {response.text}")
            except requests.RequestException as e:
                logger.error(f"Connection failure during registration: {e}")

            logger.info(f"Registration failed. Retrying in {backoff} seconds...")
            time.sleep(backoff)
            backoff = min(backoff * 2.0, max_backoff)

    def send_telemetry(self, stats: dict, packets: list[dict]) -> bool:
        """Uploads telemetry payload to server. Returns True on success, False otherwise."""
        if not self.agent_id:
            logger.error("Cannot send telemetry: Agent is not registered.")
            return False

        payload = {
            "agent_id": self.agent_id,
            "stats": stats,
            "packets": packets
        }

        try:
            response = requests.post(config.TELEMETRY_ENDPOINT, json=payload, timeout=10.0)
            if response.status_code == 200:
                logger.info(f"Successfully uploaded telemetry (packets: {len(packets)}).")
                return True
            else:
                logger.error(f"Server rejected telemetry payload (Status {response.status_code}): {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Failed to transmit telemetry to server: {e}")
            return False
