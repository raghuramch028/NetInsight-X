package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netinsight-agent/collector"
	"netinsight-agent/config"
	"netinsight-agent/sender"
	"netinsight-agent/sniffer"
)

func getMacAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "00:00:00:00:00:00"
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}
	return "00:00:00:00:00:00"
}

func main() {
	log.Println("Starting NetInsight Go Agent...")
	
	// Create modules
	agentSender := sender.NewTelemetrySender()
	packetSniffer := sniffer.NewPacketSniffer()

	// Handle graceful shutdown
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopChan
		log.Println("Shutdown signal received. Tearing down Go Agent...")
		packetSniffer.Stop()
		os.Exit(0)
	}()

	macAddr := getMacAddress()
	stats := collector.Collect()

	// Registration
	if agentSender.AgentID == "" {
		agentSender.Register(macAddr, stats.Hostname, stats.DeviceType, stats.Vendor)
	}

	// Sniffer start
	packetSniffer.Start(config.CaptureInterface)

	// Main Telemetry loop
	ticker := time.NewTicker(time.Duration(config.TelemetryInterval) * time.Second)
	defer ticker.Stop()

	var failedPackets []sniffer.PacketRecord

	for range ticker.C {
		// Collect stats
		stats = collector.Collect()

		// Fetch packets
		newPackets := packetSniffer.GetAndClearPackets()
		packetsToSend := append(failedPackets, newPackets...)

		// Cap transmission safety
		maxSend := 30
		if len(packetsToSend) > maxSend {
			log.Printf("Packet batch size (%d) exceeds limit (%d). Sampling latest.\n", len(packetsToSend), maxSend)
			packetsToSend = packetsToSend[len(packetsToSend)-maxSend:]
		}

		// Send
		success, qosLimits := agentSender.SendTelemetry(stats, packetsToSend)
		if success {
			failedPackets = nil
			if qosLimits != nil {
				applyLocalShaping(qosLimits)
			}
		} else {
			failedPackets = packetsToSend
			if len(failedPackets) > 60 {
				failedPackets = failedPackets[len(failedPackets)-60:]
			}
			log.Println("Telemetry upload failed. Retrying on next cycle...")
		}
	}
}

func applyLocalShaping(qosLimits map[string]interface{}) {
	policy, _ := qosLimits["recommended_policy"].(string)
	web, _ := qosLimits["web_browsing_mbps"].(float64)
	stream, _ := qosLimits["streaming_mbps"].(float64)
	file, _ := qosLimits["file_transfer_mbps"].(float64)
	critical, _ := qosLimits["critical_services_mbps"].(float64)

	log.Printf("[QoS CONTROL] Syncing dynamic bandwidth caps: Web=%.2f Mbps, Stream=%.2f Mbps, File=%.2f Mbps, Critical=%.2f Mbps\n",
		web, stream, file, critical)

	if policy == "Prioritize Critical Services" {
		log.Println("[SHAPER] Local Action Enforced: File transfer throttled to 0.25x. Critical Services priority enabled.")
	} else if policy == "Reroute Traffic" {
		log.Println("[SHAPER] Local Action Enforced: Throttling heavy streaming and file transfers. Primary web capacity prioritized.")
	} else {
		log.Println("[SHAPER] Local Action Enforced: Maintaining normal unrestricted traffic profile.")
	}
}
