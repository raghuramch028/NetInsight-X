package config

import (
	"os"
)

var (
	ServerURL            = "http://localhost:8000"
	RegistrationEndpoint = ServerURL + "/api/v1/agents/register"
	TelemetryEndpoint    = ServerURL + "/api/v1/agents/telemetry"
	TelemetryInterval    = 3 // seconds
	AgentIDFile         = "agent_id.txt"
	CaptureInterface    = "" // Leave empty to auto-select primary interface
	HotspotSSID         = getEnv("HOTSPOT_SSID", "SEM3_PROJECT")
	// AgentToken is sent as the X-Agent-Token header on every request. Must match
	// NETINSIGHT_AGENT_TOKEN configured on the server for the server to accept this agent's traffic
	// once token enforcement is enabled.
	AgentToken = getEnv("NETINSIGHT_AGENT_TOKEN", "")
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

// SetServerURL updates ServerURL and derives the registration/telemetry endpoints from it.
// Used both by the SERVER_URL env var and by the -server CLI flag.
func SetServerURL(url string) {
	ServerURL = url
	RegistrationEndpoint = ServerURL + "/api/v1/agents/register"
	TelemetryEndpoint = ServerURL + "/api/v1/agents/telemetry"
}

func init() {
	if val := os.Getenv("SERVER_URL"); val != "" {
		SetServerURL(val)
	}
}
