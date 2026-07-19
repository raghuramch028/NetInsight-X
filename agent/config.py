import os

# Server address configuration
SERVER_URL = os.environ.get("NETINSIGHT_SERVER_URL", "http://localhost:8000")

# API Endpoints
REGISTRATION_ENDPOINT = f"{SERVER_URL}/api/v1/agents/register"
TELEMETRY_ENDPOINT = f"{SERVER_URL}/api/v1/agents/telemetry"

# Ingestion frequency settings (in seconds)
TELEMETRY_INTERVAL = float(os.environ.get("NETINSIGHT_AGENT_INTERVAL", "3.0"))

# Bind Scapy sniffer to a specific adapter; if None, binds to default
CAPTURE_INTERFACE = os.environ.get("NETINSIGHT_AGENT_INTERFACE", None)

# Persistent file storing the assigned agent UUID
AGENT_ID_FILE = "agent_id.txt"
