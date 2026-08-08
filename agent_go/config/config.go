package config

import (
	"os"
	"strings"
)

var (
	ServerURL            = "http://localhost:8000"
	RegistrationEndpoint = "http://localhost:8000/api/v1/agents/register"
	TelemetryEndpoint    = "http://localhost:8000/api/v1/agents/telemetry"
	TelemetryInterval    = 3 // seconds
	AgentIDFile         = "agent_id.txt"
	CaptureInterface    = "" // Leave empty to auto-select primary interface
	HotspotSSID         = getEnv("HOTSPOT_SSID", "SEM3_PROJECT")
	AgentToken          = getEnv("NETINSIGHT_AGENT_TOKEN", "")
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

// SetServerURL updates ServerURL and re-derives registration and telemetry endpoints.
func SetServerURL(url string) {
	cleanURL := strings.TrimRight(url, "/")
	ServerURL = cleanURL
	RegistrationEndpoint = ServerURL + "/api/v1/agents/register"
	TelemetryEndpoint = ServerURL + "/api/v1/agents/telemetry"
}

func init() {
	if val := os.Getenv("SERVER_URL"); val != "" {
		SetServerURL(val)
	} else if val := os.Getenv("NETINSIGHT_SERVER_URL"); val != "" {
		SetServerURL(val)
	}
}
