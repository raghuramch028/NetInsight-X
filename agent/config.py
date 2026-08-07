import os

# Server address configuration — environment variable overrides default for portability
SERVER_URL = os.environ.get(
    "NETINSIGHT_SERVER_URL",
    os.environ.get("SERVER_URL", "http://localhost:8000")
)

# API Endpoints
REGISTRATION_ENDPOINT = f"{SERVER_URL}/api/v1/agents/register"
TELEMETRY_ENDPOINT = f"{SERVER_URL}/api/v1/agents/telemetry"


def set_server_url(url: str) -> None:
    """Overrides SERVER_URL and re-derives the dependent endpoint URLs. Used by main.py's
    --server CLI flag (module-level globals here are read at call-time by sender.py, so calling
    this before the agent starts making requests is sufficient — no need to reconstruct anything)."""
    global SERVER_URL, REGISTRATION_ENDPOINT, TELEMETRY_ENDPOINT
    SERVER_URL = url
    REGISTRATION_ENDPOINT = f"{SERVER_URL}/api/v1/agents/register"
    TELEMETRY_ENDPOINT = f"{SERVER_URL}/api/v1/agents/telemetry"

# Ingestion frequency settings (in seconds)
TELEMETRY_INTERVAL = float(os.environ.get("NETINSIGHT_AGENT_INTERVAL", "1.0"))

# Bind Scapy sniffer to a specific adapter; if None, binds to default
CAPTURE_INTERFACE = os.environ.get("NETINSIGHT_AGENT_INTERFACE", None)

# Persistent file storing the assigned agent UUID
AGENT_ID_FILE = "agent_id.txt"

# SSID restriction setting (if set, agent will only upload telemetry when connected to this Wi-Fi network name)

HOTSPOT_SSID = os.environ.get("NETINSIGHT_HOTSPOT_SSID", None)

# Shared secret sent as the X-Agent-Token header on every request to the central server.
# Must match NETINSIGHT_AGENT_TOKEN configured on the server for registration/telemetry to succeed
# once the server enables token enforcement.
AGENT_TOKEN = os.environ.get("NETINSIGHT_AGENT_TOKEN", None)
