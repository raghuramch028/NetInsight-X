"""NetInsight-X synthetic anomaly telemetry demo.

Sends generated packet metadata to a NetInsight-X server for a local demo.
It does not create or transmit raw attack traffic.

Usage:
    python scratch/demo_attack_simulator.py --attack ddos --server http://localhost:8000
    python scratch/demo_attack_simulator.py --attack mirai --server http://localhost:8000
    python scratch/demo_attack_simulator.py --attack recon --server http://localhost:8000
    python scratch/demo_attack_simulator.py --attack bruteforce --server http://localhost:8000
    python scratch/demo_attack_simulator.py --attack all --server http://localhost:8000
"""

import argparse
import os
import random
import time

import requests


def _auth_headers() -> dict[str, str]:
    """Return the shared agent token header when configured."""
    token = os.environ.get("NETINSIGHT_AGENT_TOKEN")
    return {"X-Agent-Token": token} if token else {}

# ── Attack Profile Definitions ──────────────────────────────────────────────
ATTACK_PROFILES = {
    "ddos": {
        "label": "DDoS (UDP Flood)",
        "description": "High-rate small UDP packet flood to exhaust network resources",
        "packets": lambda: [
            {
                "src_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                "dst_ip": "10.204.108.128",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([53, 80, 443]),
                "protocol": "UDP",
                "size": random.randint(40, 128),
                "timestamp": time.time() + i * 0.0005,
                "ttl": random.randint(32, 64),
            }
            for i in range(80)
        ],
    },
    "mirai": {
        "label": "Mirai Botnet (IoT Scanner)",
        "description": "IoT botnet telnet/scanner targeting management ports 23/2323/7547",
        "packets": lambda: [
            {
                "src_ip": f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "dst_ip": f"192.168.1.{random.randint(1,254)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([23, 2323, 7547, 5555]),
                "protocol": "UDP",
                "size": random.randint(200, 600),
                "timestamp": time.time() + i * 0.002,
                "ttl": random.randint(48, 128),
            }
            for i in range(60)
        ],
    },
    "recon": {
        "label": "Reconnaissance (Port Scan)",
        "description": "Wide port scanning probing 25+ unique destination ports for open services",
        "packets": lambda: [
            {
                "src_ip": "172.16.0.100",
                "dst_ip": "10.204.108.128",
                "src_port": random.randint(40000, 65535),
                "dst_port": 20 + i * 37 % 65535,  # Spread across many unique ports
                "protocol": "TCP",
                "size": random.randint(40, 100),
                "timestamp": time.time() + i * 0.01,
                "ttl": random.randint(64, 128),
            }
            for i in range(50)
        ],
    },
    "bruteforce": {
        "label": "Brute Force (SSH Attack)",
        "description": "Automated SSH password guessing attempts targeting port 22",
        "packets": lambda: [
            {
                "src_ip": f"10.0.{random.randint(1,50)}.{random.randint(1,254)}",
                "dst_ip": "10.204.108.128",
                "src_port": random.randint(1024, 65535),
                "dst_port": 22,
                "protocol": "TCP",
                "size": random.randint(80, 200),
                "timestamp": time.time() + i * 0.015,
                "ttl": random.randint(60, 128),
            }
            for i in range(40)
        ],
    },
}


def register_attacker_agent(server_url: str) -> str | None:
    """Registers a synthetic demo agent with the server and returns its agent_id."""
    fake_mac = "de:ad:be:ef:{:02x}:{:02x}".format(
        random.randint(0, 255), random.randint(0, 255)
    )
    payload = {
        "mac_address": fake_mac,
        "hostname": "Synthetic-Demo-Agent",
        "device_type": "Simulated Attacker Node",
        "vendor": "NetInsight-X Demo Tool",
        "ip_address": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
    }
    try:
        resp = requests.post(
            f"{server_url}/api/v1/agents/register",
            json=payload,
            headers=_auth_headers(),
            timeout=5,
        )
        if resp.status_code == 200:
            agent_id = resp.json().get("agent_id")
            print(f"  [OK] Attacker agent registered (ID: {agent_id}, MAC: {fake_mac})")
            return agent_id
        else:
            print(f"  [ERROR] Registration failed: {resp.status_code} — {resp.text}")
            return None
    except requests.ConnectionError:
        print(f"  [ERROR] Cannot connect to server at {server_url}")
        print("         Make sure the Django server is running: python manage.py runserver 0.0.0.0:8000")
        return None


def send_attack_telemetry(server_url: str, agent_id: str, attack_type: str):
    """Sends generated packet metadata to the server for classification."""
    profile = ATTACK_PROFILES[attack_type]
    packets = profile["packets"]()

    payload = {
        "agent_id": agent_id,
        "stats": {
            "hostname": "Synthetic-Demo-Agent",
            "cpu_usage": random.uniform(75, 99),
            "memory_usage": random.uniform(60, 90),
            "disk_usage": random.uniform(30, 60),
            "bytes_sent": random.randint(500000, 5000000),
            "bytes_recv": random.randint(100000, 1000000),
            "active_connections": random.randint(50, 500),
        },
        "packets": packets,
    }

    try:
        resp = requests.post(
            f"{server_url}/api/v1/agents/telemetry",
            json=payload,
            headers=_auth_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            print(f"  [OK] Sent {len(packets)} {profile['label']} packets → Server accepted")
        else:
            print(f"  [WARN] Server responded with {resp.status_code}: {resp.text}")
    except requests.ConnectionError:
        print(f"  [ERROR] Connection lost to {server_url}")


def run_attack(server_url: str, attack_type: str, waves: int = 3, delay: float = 2.0):
    """Sends one or more waves of synthetic anomaly telemetry."""
    profile = ATTACK_PROFILES[attack_type]

    print(f"\n{'='*60}")
    print(f"  SYNTHETIC ANOMALY DEMO: {profile['label']}")
    print(f"  {profile['description']}")
    print(f"  Demo server: {server_url}")
    print(f"  Waves: {waves} | Delay: {delay}s between waves")
    print(f"{'='*60}\n")

    # Register attacker agent
    print("[1/2] Registering attacker agent...")
    agent_id = register_attacker_agent(server_url)
    if not agent_id:
        print("\n  FAILED: Could not register attacker agent. Aborting.\n")
        return False

    # Send attack waves
    print(f"\n[2/2] Sending {attack_type.upper()} synthetic telemetry...\n")
    for wave in range(1, waves + 1):
        print(f"  Wave {wave}/{waves}:")
        send_attack_telemetry(server_url, agent_id, attack_type)
        if wave < waves:
            print(f"  Waiting {delay}s before next wave...")
            time.sleep(delay)

    print(f"\n  DEMO COMPLETE. Check the classification results at {server_url}/classification/\n")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="NetInsight-X Synthetic Anomaly Demo — send generated packet metadata; no raw attack traffic is generated.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Synthetic Profiles:
    ddos         Synthetic DDoS-like flow metadata
    mirai        Synthetic IoT-scanner-like flow metadata
    recon        Synthetic reconnaissance-like flow metadata
    bruteforce   Synthetic SSH brute-force-like flow metadata
    all          Run all profiles sequentially

Examples:
  python scratch/demo_attack_simulator.py --attack ddos
  python scratch/demo_attack_simulator.py --attack all --server http://10.204.108.128:8000
        """,
    )
    parser.add_argument(
        "--attack",
        type=str,
        default="all",
        choices=["ddos", "mirai", "recon", "bruteforce", "all"],
        help="Synthetic anomaly profile to send (default: all)",
    )
    parser.add_argument(
        "--server",
        type=str,
        default="http://localhost:8000",
        help="NetInsight-X server URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--waves",
        type=int,
        default=3,
        help="Number of attack waves per attack type (default: 3)",
    )

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  NetInsight-X — SYNTHETIC ANOMALY DEMO")
    print("  Sends generated telemetry metadata only; no raw attack traffic")
    print("=" * 60)

    if args.attack == "all":
        attack_types = ["ddos", "mirai", "recon", "bruteforce"]
    else:
        attack_types = [args.attack]

    success_count = 0
    for attack_type in attack_types:
        if run_attack(args.server, attack_type, waves=args.waves):
            success_count += 1
        time.sleep(1.0)

    print(f"\n{'='*60}")
    print(f"  SIMULATION COMPLETE: {success_count}/{len(attack_types)} demo profiles sent successfully")
    print(f"  Open your dashboard: {args.server}/classification/")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
