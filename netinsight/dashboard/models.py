import uuid
from django.db import models

class Agent(models.Model):
    """Tracks active telemetry agent endpoints using unique MAC addresses."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mac_address = models.CharField(max_length=17, unique=True, db_index=True)
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    device_type = models.CharField(max_length=100)
    vendor = models.CharField(max_length=255)
    last_seen = models.DateTimeField(auto_now=True)
    cpu_usage = models.FloatField(default=0.0)
    memory_usage = models.FloatField(default=0.0)
    disk_usage = models.FloatField(default=0.0)
    bytes_sent = models.BigIntegerField(default=0)
    bytes_recv = models.BigIntegerField(default=0)
    active_connections = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.hostname} ({self.mac_address})"

class PacketRecord(models.Model):
    """Logs individual raw packet headers captured by client agents (pruned regularly)."""
    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name="packets")
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=20)
    size = models.IntegerField()
    ttl = models.IntegerField()
    timestamp = models.FloatField(db_index=True)

    def __str__(self):
        return f"{self.protocol} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"

class FlowRecord(models.Model):
    """Summarizes packet flows grouped by active IP flows for analysis and SVM classification."""
    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name="flows")
    flow_key = models.CharField(max_length=255, db_index=True)
    start_time = models.FloatField()
    end_time = models.FloatField()
    duration = models.FloatField()
    packet_count = models.IntegerField(default=0)
    byte_count = models.BigIntegerField(default=0)
    avg_packet_size = models.FloatField(default=0.0)
    protocol = models.CharField(max_length=20)
    threat_label = models.CharField(max_length=100, default="Normal")

    def __str__(self):
        return f"Flow {self.flow_key} ({self.threat_label})"

class MetricRecord(models.Model):
    """Stores calculated network-wide performance metrics."""
    timestamp = models.FloatField(primary_key=True, db_index=True)
    throughput = models.FloatField(default=0.0)
    packet_rate = models.FloatField(default=0.0)
    bandwidth_util = models.FloatField(default=0.0)
    latency = models.FloatField(default=0.0)
    packet_loss = models.FloatField(default=0.0)

    def __str__(self):
        return f"Metrics @ {self.timestamp} (Throughput: {self.throughput/1e6:.2f} Mbps)"

class StateHistory(models.Model):
    """Logs the operational network states over time based on HMM outputs."""
    timestamp = models.FloatField(primary_key=True, db_index=True)
    network_state = models.CharField(max_length=50) # Normal, Busy, Congested, Under Attack, Recovering
    bandwidth_utilization = models.FloatField(default=0.0)
    packet_loss = models.FloatField(default=0.0)
    latency = models.FloatField(default=0.0)

    def __str__(self):
        return f"State: {self.network_state} @ {self.timestamp}"

class ThreatHistory(models.Model):
    """Stores classifications for dynamic security metrics and auditing."""
    id = models.BigAutoField(primary_key=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name="threats")
    threat_type = models.CharField(max_length=100) # Normal, DoS, DDoS, Mirai, etc.
    severity = models.CharField(max_length=20) # Information, Warning, Critical

    def __str__(self):
        return f"[{self.severity}] {self.threat_type} detected on {self.agent.hostname}"

class SystemSettings(models.Model):
    """Stores system-wide threshold policies and settings dynamically."""
    bandwidth_threshold = models.FloatField(default=0.75) # 75%
    loss_threshold = models.FloatField(default=0.05) # 5%
    latency_threshold = models.FloatField(default=0.15) # 150ms
    hmm_thresholds = models.JSONField(default=dict)
    lp_priorities = models.JSONField(default=list)
    svm_confidence_threshold = models.FloatField(default=0.80)

    def __str__(self):
        return "SystemSettings Policy Defaults"
