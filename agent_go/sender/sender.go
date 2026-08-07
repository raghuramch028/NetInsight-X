package sender

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"netinsight-agent/collector"
	"netinsight-agent/config"
	"netinsight-agent/sniffer"
)

type TelemetrySender struct {
	AgentID    string
	httpClient *http.Client
	// LastRTTSeconds holds the round-trip time of the most recent successful telemetry POST.
	// nil until the first successful upload completes.
	LastRTTSeconds *float64
}

func NewTelemetrySender() *TelemetrySender {
	s := &TelemetrySender{httpClient: &http.Client{Timeout: 10 * time.Second}}
	s.LoadAgentID()
	return s
}

// postJSON sends a JSON payload via POST, attaching the X-Agent-Token header when configured.
func (s *TelemetrySender) postJSON(url string, jsonPayload []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if config.AgentToken != "" {
		req.Header.Set("X-Agent-Token", config.AgentToken)
	}
	return s.httpClient.Do(req)
}

func (s *TelemetrySender) LoadAgentID() {
	if _, err := os.Stat(config.AgentIDFile); err == nil {
		data, err := os.ReadFile(config.AgentIDFile)
		if err == nil {
			s.AgentID = strings.TrimSpace(string(data))
			log.Printf("Loaded existing Go Agent ID: %s\n", s.AgentID)
		}
	}
}

func (s *TelemetrySender) SaveAgentID(agentID string) {
	err := os.WriteFile(config.AgentIDFile, []byte(agentID), 0644)
	if err == nil {
		s.AgentID = agentID
		log.Printf("Saved Go Agent ID: %s\n", agentID)
	} else {
		log.Printf("Error saving agent ID: %v\n", err)
	}
}

func (s *TelemetrySender) Register(macAddress, hostname, deviceType, vendor string) {
	payload := map[string]string{
		"mac_address": macAddress,
		"hostname":    hostname,
		"device_type": deviceType,
		"vendor":      vendor,
	}

	for {
		log.Printf("Registering Go Agent at %s...\n", config.RegistrationEndpoint)
		jsonPayload, _ := json.Marshal(payload)
		resp, err := s.postJSON(config.RegistrationEndpoint, jsonPayload)
		if err == nil {
			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				var data map[string]interface{}
				if err := json.Unmarshal(body, &data); err == nil {
					if agentID, ok := data["agent_id"].(string); ok {
						s.SaveAgentID(agentID)
						log.Println("Go Agent registration successful.")
						return
					}
				}
			} else if resp.StatusCode == 401 {
				resp.Body.Close()
				log.Println("Server rejected registration (401 Unauthorized). Check that NETINSIGHT_AGENT_TOKEN " +
					"on this agent matches the server's configured token.")
			} else {
				resp.Body.Close()
			}
		}
		log.Println("Registration failed. Retrying in 3.0 seconds...")
		time.Sleep(3 * time.Second)
	}
}

func (s *TelemetrySender) SendTelemetry(stats collector.Stats, packets []sniffer.PacketRecord) (bool, map[string]interface{}) {
	if s.AgentID == "" {
		log.Println("Cannot send telemetry: Agent not registered.")
		return false, nil
	}

	payload := map[string]interface{}{
		"agent_id": s.AgentID,
		"stats":    stats,
		"packets":  packets,
	}

	jsonPayload, _ := json.Marshal(payload)
	requestStart := time.Now()
	resp, err := s.postJSON(config.TelemetryEndpoint, jsonPayload)
	if err != nil {
		log.Printf("Failed to transmit telemetry to server: %v\n", err)
		return false, nil
	}
	defer resp.Body.Close()

	rtt := time.Since(requestStart).Seconds()
	s.LastRTTSeconds = &rtt

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		var data map[string]interface{}
		json.Unmarshal(body, &data)
		qos, _ := data["enforced_qos"].(map[string]interface{})
		return true, qos
	} else if resp.StatusCode == 404 {
		log.Println("Server reported agent is not registered. Clearing invalid ID.")
		os.Remove(config.AgentIDFile)
		s.AgentID = ""
		return false, nil
	} else if resp.StatusCode == 401 {
		log.Println("Server rejected telemetry (401 Unauthorized). Check that NETINSIGHT_AGENT_TOKEN on this " +
			"agent matches the server's configured token.")
		return false, nil
	}

	return false, nil
}
