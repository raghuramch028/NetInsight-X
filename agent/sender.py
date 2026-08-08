import os
import time

import requests

from agent import config
from agent.logger import logger
from agent.utils import get_current_ssid


class TelemetrySender:
    """Handles communications with the central Django API. Implements backoff retries."""

    def __init__(self):
        self.agent_id = self.load_agent_id()
        # Round-trip time of the most recent successful telemetry POST, in seconds. Reported on
        # the *following* cycle's stats payload (rtt_seconds) since a request obviously can't
        # report its own duration. Replaces a previous hardcoded server-side latency constant.
        self.last_rtt_seconds: float | None = None

    def _auth_headers(self) -> dict:
        """Builds the X-Agent-Token header when NETINSIGHT_AGENT_TOKEN is configured locally."""
        if config.AGENT_TOKEN:
            return {"X-Agent-Token": config.AGENT_TOKEN}
        return {}

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
            "vendor": vendor,
            "ssid": get_current_ssid()
        }

        while True:
            logger.info(f"Attempting to register agent at {config.REGISTRATION_ENDPOINT}...")
            try:
                response = requests.post(
                    config.REGISTRATION_ENDPOINT, json=payload, headers=self._auth_headers(), timeout=10.0
                )
                if response.status_code == 200 or response.status_code == 201:
                    data = response.json()
                    agent_id = data.get("agent_id")
                    if agent_id:
                        self.save_agent_id(agent_id)
                        logger.info("Agent registration successful.")
                        return True
                    else:
                        logger.error("Registration response did not contain 'agent_id'.")
                elif response.status_code == 403:
                    logger.error(f"Server rejected registration (403 Forbidden): {response.text}")
                elif response.status_code == 401:
                    logger.error(
                        "Server rejected registration (401 Unauthorized). The server has agent-token "
                        "enforcement enabled but this agent's NETINSIGHT_AGENT_TOKEN is missing or does not "
                        "match. Set NETINSIGHT_AGENT_TOKEN in this agent's environment to the same value "
                        "configured on the server."
                    )
                else:
                    logger.error(f"Server rejected registration (Status: {response.status_code}): {response.text}")
            except requests.RequestException as e:
                logger.error(f"Connection failure during registration: {e}")

            logger.info("Registration failed. Retrying in 1.0 second...")
            time.sleep(1.0)

    def send_telemetry(self, stats: dict, packets: list[dict]) -> tuple[bool, dict | None]:
        """Uploads telemetry payload to server. Returns (success, enforced_qos)."""
        if not self.agent_id:
            logger.error("Cannot send telemetry: Agent is not registered.")
            return False, None

        payload = {
            "agent_id": self.agent_id,
            "stats": stats,
            "packets": packets,
            "ssid": get_current_ssid()
        }

        try:
            request_start = time.time()
            response = requests.post(
                config.TELEMETRY_ENDPOINT, json=payload, headers=self._auth_headers(), timeout=10.0
            )
            self.last_rtt_seconds = time.time() - request_start
            if response.status_code == 200:
                logger.info(f"Successfully uploaded telemetry (packets: {len(packets)}).")
                data = response.json()
                return True, data.get("enforced_qos")
            elif response.status_code == 404:
                logger.error("Server reported agent is not registered (Status 404). Clearing invalid local agent ID.")
                if os.path.exists(config.AGENT_ID_FILE):
                    try:
                        os.remove(config.AGENT_ID_FILE)
                    except Exception as e:
                        logger.error(f"Failed to delete invalid agent ID file: {e}")
                self.agent_id = None
                return False, None
            elif response.status_code == 401:
                logger.error(
                    "Server rejected telemetry (401 Unauthorized). Check that NETINSIGHT_AGENT_TOKEN on this "
                    "agent matches the server's configured token."
                )
                return False, None
            else:
                logger.error(f"Server rejected telemetry payload (Status {response.status_code}): {response.text}")
                return False, None
        except requests.RequestException as e:
            logger.error(f"Failed to transmit telemetry to server: {e}")
            return False, None
