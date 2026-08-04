package config

import (
	"os"
)

var (
	ServerURL            = "http://localhost:8000"
	RegistrationEndpoint = ServerURL + "/dashboard/api/agent/register/"
	TelemetryEndpoint    = ServerURL + "/dashboard/api/agent/telemetry/"
	TelemetryInterval    = 3 // seconds
	AgentIDFile         = "agent_id.txt"
	CaptureInterface    = "" // Leave empty to auto-select primary interface
	HotspotSSID         = "SEM3_PROJECT"
)

func init() {
	if val := os.Getenv("SERVER_URL"); val != "" {
		ServerURL = val
		RegistrationEndpoint = ServerURL + "/dashboard/api/agent/register/"
		TelemetryEndpoint = ServerURL + "/dashboard/api/agent/telemetry/"
	}
}
