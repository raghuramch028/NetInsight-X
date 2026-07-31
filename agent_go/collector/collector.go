package collector

import (
	"context"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
)

type Stats struct {
	Hostname          string  `json:"hostname"`
	IPAddress         string  `json:"ip_address"`
	DeviceType        string  `json:"device_type"`
	Vendor            string  `json:"vendor"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemoryUsage       float64 `json:"memory_usage"`
	DiskUsage         float64 `json:"disk_usage"`
	BytesSent         uint64  `json:"bytes_sent"`
	BytesRecv         uint64  `json:"bytes_recv"`
	ActiveConnections int     `json:"active_connections"`
}

func GetPrimaryIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		hostname, err := os.Hostname()
		if err != nil {
			return "127.0.0.1"
		}
		addrs, err := net.LookupHost(hostname)
		if err != nil || len(addrs) == 0 {
			return "127.0.0.1"
		}
		return addrs[0]
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func GetActiveConnections() int {
	conns, err := psnet.ConnectionsWithContext(context.Background(), "all")
	if err != nil {
		return 0
	}
	active := 0
	for _, c := range conns {
		if c.Status == "ESTABLISHED" || c.Status == "LISTEN" {
			active++
		}
	}
	return active
}

func Collect() Stats {
	hostname, _ := os.Hostname()
	vm, _ := mem.VirtualMemory()
	d, _ := disk.Usage("/")
	if d == nil {
		d, _ = disk.Usage("C:")
	}

	cpuPerc, _ := cpu.Percent(100*time.Millisecond, false)
	var cpuVal float64
	if len(cpuPerc) > 0 {
		cpuVal = cpuPerc[0]
	}

	io, _ := psnet.IOCounters(false)
	var sent, recv uint64
	if len(io) > 0 {
		sent = io[0].BytesSent
		recv = io[0].BytesRecv
	}

	memUsage := 0.0
	if vm != nil {
		memUsage = vm.UsedPercent
	}
	diskUsagePercent := 0.0
	if d != nil {
		diskUsagePercent = d.UsedPercent
	}

	return Stats{
		Hostname:          hostname,
		IPAddress:         GetPrimaryIP(),
		DeviceType:        runtime.GOOS + " " + runtime.GOARCH,
		Vendor:            runtime.Compiler,
		CPUUsage:          cpuVal,
		MemoryUsage:       memUsage,
		DiskUsage:         diskUsagePercent,
		BytesSent:         sent,
		BytesRecv:         recv,
		ActiveConnections: GetActiveConnections(),
	}
}
