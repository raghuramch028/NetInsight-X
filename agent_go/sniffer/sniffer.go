package sniffer

import (
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketRecord struct {
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
	SrcPort   int     `json:"src_port"`
	DstPort   int     `json:"dst_port"`
	Protocol  string  `json:"protocol"`
	Size      int     `json:"size"`
	TTL       uint8   `json:"ttl"`
	Timestamp float64 `json:"timestamp"`
	// TCPSeq is the TCP sequence number (nil for non-TCP packets), letting the server detect
	// true retransmissions (same segment sent twice) instead of only an approximate
	// duplicate-packet heuristic.
	TCPSeq *uint32 `json:"tcp_seq,omitempty"`
}

type PacketSniffer struct {
	packetBuffer []PacketRecord
	bufferLock   sync.Mutex
	isRunning    bool
	handle       *pcap.Handle
	stopChan     chan struct{}
}

func NewPacketSniffer() *PacketSniffer {
	return &PacketSniffer{
		packetBuffer: make([]PacketRecord, 0),
		stopChan:     make(chan struct{}),
	}
}

func (s *PacketSniffer) Start(device string) {
	if s.isRunning {
		return
	}

	if device == "" {
		// Auto-detect device
		devices, err := pcap.FindAllDevs()
		if err != nil || len(devices) == 0 {
			log.Println("Error finding capture devices")
			return
		}
		// Default to first active device
		device = devices[0].Name
	}

	var err error
	s.handle, err = pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening device %s: %v\n", device, err)
		return
	}

	s.isRunning = true
	s.stopChan = make(chan struct{})

	go func() {
		packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
		packets := packetSource.Packets()

		for {
			select {
			case packet := <-packets:
				if packet == nil {
					return
				}
				s.processPacket(packet)
			case <-s.stopChan:
				return
			}
		}
	}()
	log.Printf("Go Sniffer started on interface: %s\n", device)
}

func (s *PacketSniffer) Stop() {
	if !s.isRunning {
		return
	}
	s.isRunning = false
	close(s.stopChan)
	if s.handle != nil {
		s.handle.Close()
	}
	log.Println("Go Sniffer stopped.")
}

func (s *PacketSniffer) processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	ttl := ip.TTL
	size := len(packet.Data())

	srcPort := 0
	dstPort := 0
	protocol := "OTHER"
	var tcpSeq *uint32

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
		protocol = "TCP"
		seq := tcp.Seq
		tcpSeq = &seq
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
			protocol = "UDP"
		} else {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer != nil {
				protocol = "ICMP"
			} else if ip.Protocol == 2 {
				protocol = "IGMP"
			} else {
				protocol = fmt.Sprintf("OTHER(%d)", ip.Protocol)
			}
		}
	}

	record := PacketRecord{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		Size:      size,
		TTL:       ttl,
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		TCPSeq:    tcpSeq,
	}

	s.bufferLock.Lock()
	defer s.bufferLock.Unlock()
	s.packetBuffer = append(s.packetBuffer, record)
	if len(s.packetBuffer) > 10000 {
		s.packetBuffer = s.packetBuffer[1:]
	}
}

func (s *PacketSniffer) GetAndClearPackets() []PacketRecord {
	s.bufferLock.Lock()
	defer s.bufferLock.Unlock()
	pkts := s.packetBuffer
	s.packetBuffer = make([]PacketRecord, 0)
	return pkts
}
