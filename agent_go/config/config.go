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
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func init() {
	if val := os.Getenv("SERVER_URL"); val != "" {
		ServerURL = val
		RegistrationEndpoint = ServerURL + "/api/v1/agents/register"
		TelemetryEndpoint = ServerURL + "/api/v1/agents/telemetry"
	}
}
