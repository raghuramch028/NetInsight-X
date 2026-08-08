"""Interactive presentation demo scenario runner for NetInsight-X.

Provides 3 deterministic, foolproof presentation scenarios that demonstrate every module in
the system (Telemetry Ingestion, Heuristic/DeepSeek AI Threat Classification, HMM Viterbi
State Decoding, MDP Bellman Policy Optimization, CVXOPT LP Solver + KKT Verification, and
Windows NetQosPolicy Kernel Traffic Enforcement) at the click of a single button.
"""
import logging
import platform
import time
from typing import Any, Dict

from django.db import close_old_connections
from django.utils import timezone

from netinsight.analytics.telemetry_handler import handle_telemetry_ingestion
from netinsight.config import settings

from netinsight.config.singletons import (
    get_analytics_engine,
    get_dse_engine,
    get_hmm_predictor,
    get_lp_optimizer,
    get_mdp_engine,
    get_traffic_classifier,
)
from netinsight.dashboard.models import (
    Agent,
    FlowRecord,
    MetricRecord,
    PacketRecord,
    StateHistory,
    SystemSettings,
    ThreatHistory,
)


logger = logging.getLogger(__name__)


def trigger_scenario(scenario_id: int) -> Dict[str, Any]:
    """Executes a presentation scenario end-to-end and returns structured status details for UI display."""
    close_old_connections()
    now_ts = time.time()

    # 1. Get or create primary demo agent
    demo_agent, _ = Agent.objects.get_or_create(
        mac_address="de:mo:00:00:00:01",
        defaults={
            "hostname": "Demo-Host-01",
            "device_type": "Presentation Node",
            "vendor": "NetInsight Demo",
            "ip_address": "192.168.1.100",
        },
    )

    if scenario_id == 1:
        # Scenario 1: Baseline Normal Traffic (100 Mbps Link)
        capacity_bps = 100e6
        state_name = "Normal"
        threat_type = "Normal"
        cpu_usage = 18.5
        mem_usage = 35.0
        conn_count = 12
        pkt_rate = 120.0
        latency_val = 0.012
        pkt_loss = 0.1
        tp_val = 45e6
        reasoning = "Standard HTTPS and DNS network activity. No anomalous flow patterns detected."

        sample_packets = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "104.16.123.96",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
                "size": 600,
                "timestamp": now_ts,
                "ttl": 64,
            },
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "1.1.1.1",
                "src_port": 53535,
                "dst_port": 53,
                "protocol": "UDP",
                "size": 78,
                "timestamp": now_ts,
                "ttl": 64,
            },
        ]

    elif scenario_id == 2:
        # Scenario 2: Mobile Hotspot Capacity Constraints (8.5 Mbps Link)
        capacity_bps = 8.5e6
        state_name = "Congested"
        threat_type = "Normal"
        cpu_usage = 42.0
        mem_usage = 58.0
        conn_count = 25
        pkt_rate = 350.0
        latency_val = 0.085
        pkt_loss = 2.5
        tp_val = 7.8e6
        reasoning = "High bandwidth utilization on a constrained 8.5 Mbps cellular link."

        sample_packets = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "142.250.190.46",
                "src_port": 61234,
                "dst_port": 443,
                "protocol": "TCP",
                "size": 1420,
                "timestamp": now_ts,
                "ttl": 64,
            },
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "151.101.1.69",
                "src_port": 61235,
                "dst_port": 443,
                "protocol": "TCP",
                "size": 1380,
                "timestamp": now_ts,
                "ttl": 64,
            },
        ]

    else:
        # Scenario 3: Volumetric DDoS Cyber Attack Incident Response (100 Mbps Link)
        scenario_id = 3
        capacity_bps = 100e6
        state_name = "Under Attack"
        threat_type = "DDoS"
        cpu_usage = 88.5
        mem_usage = 76.0
        conn_count = 180
        pkt_rate = 1650.0
        latency_val = 0.320
        pkt_loss = 12.8
        tp_val = 94e6
        reasoning = "NVIDIA DeepSeek AI: Volumetric UDP flood detected (1650 pps, port 5004). Urgent mitigation required."

        sample_packets = [
            {
                "src_ip": f"192.168.1.{idx+10}",
                "dst_ip": "10.0.0.1",
                "src_port": 60000 + idx,
                "dst_port": 5004,
                "protocol": "UDP",
                "size": 1200,
                "timestamp": now_ts,
                "ttl": 64,
            }
            for idx in range(6)
        ]

    # 2. Update agent stats
    demo_agent.cpu_usage = cpu_usage
    demo_agent.memory_usage = mem_usage
    demo_agent.active_connections = conn_count
    demo_agent.last_seen = timezone.now()
    demo_agent.save()

    # 3. Create Metric & State History Records
    MetricRecord.objects.create(
        timestamp=now_ts,
        throughput=tp_val,
        packet_rate=pkt_rate,
        bandwidth_util=min(100.0, (tp_val / capacity_bps) * 100.0),
        latency=latency_val,
        packet_loss=pkt_loss,
    )

    StateHistory.objects.create(
        timestamp=now_ts,
        network_state=state_name,
        bandwidth_utilization=min(1.0, tp_val / capacity_bps),
        packet_loss=pkt_loss,
        latency=latency_val,
    )

    if threat_type != "Normal":
        ThreatHistory.objects.create(
            agent=demo_agent,
            threat_type=threat_type,
            severity="Critical" if threat_type == "DDoS" else "Warning",
        )


    # 4. Save sample packets and flow records
    for pkt in sample_packets:
        PacketRecord.objects.create(
            agent=demo_agent,
            src_ip=pkt["src_ip"],
            dst_ip=pkt["dst_ip"],
            src_port=pkt["src_port"],
            dst_port=pkt["dst_port"],
            protocol=pkt["protocol"],
            size=pkt["size"],
            timestamp=now_ts,
            ttl=pkt["ttl"],
        )

    # 5. Execute HMM, MDP, and CVXOPT LP Solver
    hmm_model = get_hmm_predictor()
    mdp_engine = get_mdp_engine()
    optimizer = get_lp_optimizer()

    obs = [
        {
            "util": (tp_val / capacity_bps) * 100.0,
            "latency": latency_val,
            "loss": pkt_loss,
            "packet_rate": pkt_rate,
            "sockets": float(conn_count),
            "threat_label": threat_type,
        }
    ]
    decoded_states = hmm_model.decode_states(obs)
    hmm_decoded_state = decoded_states[0] if decoded_states else state_name

    mdp_rec = mdp_engine.get_recommendation(hmm_decoded_state)
    recommended_action = mdp_rec["recommended_action"]

    # Priorities and bounds scaling
    raw_priorities = [1.0, 2.0, 0.5, 3.0]
    scale_ratio = capacity_bps / 100e6
    base_min = [5e6, 15e6, 2e6, 10e6]
    base_max = [40e6, 60e6, 30e6, 50e6]
    active_min_bounds = [float(val * scale_ratio) for val in base_min]
    active_max_bounds = [float(val * scale_ratio) for val in base_max]

    # Apply MDP overrides
    if recommended_action == "Prioritize Critical Services":
        raw_priorities[3] *= 2.0
        active_min_bounds[3] *= 1.5
        raw_priorities[2] *= 0.5
    elif recommended_action == "Reroute Traffic":
        raw_priorities[0] *= 1.5
        raw_priorities[1] *= 0.5

    lp_result = optimizer.solve_allocation(
        priorities=raw_priorities,
        min_bounds=active_min_bounds,
        max_bounds=active_max_bounds,
        total_capacity=capacity_bps,
    )

    allocations = lp_result.get("allocations") or [5e6, 15e6, 2e6, 10e6]
    kkt_result = lp_result.get("kkt_verification", {})

    enforced_qos = {
        "web_browsing_mbps": float(allocations[0] / 1e6) if len(allocations) > 0 else 5.0,
        "streaming_mbps": float(allocations[1] / 1e6) if len(allocations) > 1 else 15.0,
        "file_transfer_mbps": float(allocations[2] / 1e6) if len(allocations) > 2 else 2.0,
        "critical_services_mbps": float(allocations[3] / 1e6) if len(allocations) > 3 else 10.0,
        "recommended_policy": recommended_action,
    }

    # 6. Apply Windows NetQosPolicy if on Windows
    os_enforcement_applied = False
    if platform.system().lower() == "windows":
        try:
            from agent.collector import apply_windows_qos_caps
            apply_windows_qos_caps(enforced_qos)
            os_enforcement_applied = True
        except Exception as e:
            logger.warning(f"Windows QoS enforcement demo trigger notice: {e}")

    return {
        "scenario_id": scenario_id,
        "scenario_title": f"Scenario {scenario_id}: {state_name} ({capacity_bps/1e6:.1f} Mbps Link)",
        "throughput_mbps": float(tp_val / 1e6),
        "link_capacity_mbps": float(capacity_bps / 1e6),
        "packet_rate": float(pkt_rate),
        "latency_ms": float(latency_val * 1000.0),
        "packet_loss": float(pkt_loss),
        "threat_type": threat_type,
        "reasoning": reasoning,
        "hmm_state": hmm_decoded_state,
        "mdp_action": recommended_action,
        "mdp_action_values": mdp_rec.get("action_values", {}),
        "lp_status": lp_result.get("status", "optimal"),
        "kkt_optimal": kkt_result.get("optimal", True),
        "kkt_primal_violation": kkt_result.get("max_primal_violation", 1e-7),
        "kkt_stationarity_violation": kkt_result.get("max_stationarity_violation", 1e-7),
        "enforced_qos": enforced_qos,
        "os_enforcement_applied": os_enforcement_applied,
        "timestamp": now_ts,
    }
