import random
import sys
import time

import requests

SERVER_URL = "http://127.0.0.1:8000"
if len(sys.argv) > 1:
    SERVER_URL = sys.argv[1].rstrip('/')

print("=========================================================")
print("   NetInsight-X Closed-Loop Telemetry & QoS Simulator   ")
print("=========================================================")
print(f"Target Server: {SERVER_URL}\n")

# 1. Register synthetic agent
mac = "00:1A:2B:3C:4D:5E"
hostname = "Simulated-Laptop-Host"

print(f"[STEP 1] Registering agent device ({hostname} - {mac})...")
try:
    reg_res = requests.post(
        f"{SERVER_URL}/api/v1/agents/register",
        json={"mac_address": mac, "hostname": hostname, "device_type": "Windows 11 Pro", "vendor": "Dell Inc."},
        timeout=5
    )
    if reg_res.status_code == 200:
        data = reg_res.json()
        agent_id = data.get("agent_id")
        print(f" -> Registration SUCCESS! Assigned Agent ID: {agent_id}\n")
    else:
        print(f" -> Registration failed with HTTP {reg_res.status_code}. Using default ID: 1\n")
        agent_id = 1
except Exception as e:
    print(f" -> Server not reachable ({e}). Running in offline display mode.\n")
    agent_id = 1

# 2. Simulate 4 Scenarios
scenarios = [
    {"name": "Normal Web Browsing", "rate": 100.0, "size": 600, "proto": "TCP", "port": 443, "latency": 0.012},
    {"name": "High Volume Traffic / Congestion", "rate": 350.0, "size": 1400, "proto": "TCP", "port": 80, "latency": 0.085},
    {"name": "DDoS Threat Attack", "rate": 1200.0, "size": 120, "proto": "UDP", "port": 5004, "latency": 0.280},
    {"name": "Post-Attack Normalization", "rate": 80.0, "size": 500, "proto": "TCP", "port": 443, "latency": 0.015}
]

for idx, sc in enumerate(scenarios, 1):
    print("---------------------------------------------------------")
    print(f"[SCENARIO {idx}] Triggering Event: {sc['name']}")
    print(f" -> Injecting: Rate={sc['rate']} pkts/s, Size={sc['size']}B, Proto={sc['proto']}, Latency={sc['latency']*1000:.1f}ms")

    payload = {
        "agent_id": agent_id,
        "mac_address": mac,
        "hostname": hostname,
        "stats": {
            "bytes_sent": random.randint(100000, 500000),
            "bytes_recv": random.randint(500000, 2000000),
            "active_connections": random.randint(5, 30),
            "packet_rate": sc['rate'],
            "avg_latency": sc['latency'],
            "packet_loss": 0.1 if idx == 1 else (1.5 if idx == 2 else 12.0)
        },
        "packets": [
            {
                "src_ip": "192.168.1.50",
                "dst_ip": "104.16.123.96",
                "src_port": 54321,
                "dst_port": sc['port'],
                "protocol": sc['proto'],
                "size": sc['size'],
                "ttl": 64,
                "timestamp": time.time(),
                "latency_est": sc['latency']
            }
        ]
    }

    try:
        res = requests.post(f"{SERVER_URL}/api/v1/agents/telemetry", json=payload, timeout=5)
        if res.status_code == 200:
            resp_data = res.json()
            enforced = resp_data.get("enforced_qos", {})
            print(" -> SERVER RESPONSE: [HTTP 200 OK]")
            print(f"    - Policy Recommended : {enforced.get('recommended_policy', 'N/A')}")
            print(f"    - Web Mbps           : {enforced.get('web_browsing_mbps', 0):.2f} Mbps")
            print(f"    - Streaming Mbps     : {enforced.get('streaming_mbps', 0):.2f} Mbps")
            print(f"    - File Transfer Mbps : {enforced.get('file_transfer_mbps', 0):.2f} Mbps (Throttled Limit)")
            print(f"    - Critical Services  : {enforced.get('critical_services_mbps', 0):.2f} Mbps")
        else:
            print(f" -> Server returned status {res.status_code}")
    except Exception as err:
        print(f" -> Could not send telemetry to {SERVER_URL}: {err}")

    time.sleep(2)

print("\n=========================================================")
print(" Demonstration Simulation Completed Successfully!")
print("=========================================================")
