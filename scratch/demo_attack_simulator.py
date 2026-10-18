"""Controlled, existing-agent XGBoost/firewall demonstration.

This tool never registers a synthetic agent and never injects packet metadata into
NetInsight. Replay mode sends exactly 40 small UDP datagrams at 2 packets/second
to a private receiver that the operator controls. The already-running local agent
must capture and upload them for classification and enforcement.
"""

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKET_COUNT = 40
PACKET_INTERVAL_SECONDS = 0.5
DEMO_EVENT_LIFETIME_SECONDS = 120
POLL_INTERVAL_SECONDS = 1.0


def auth_headers() -> dict[str, str]:
    token = os.environ.get("NETINSIGHT_AGENT_TOKEN")
    return {"X-Agent-Token": token} if token else {}


def validate_private_receiver(raw_ip: str, port: int) -> str:
    receiver = ipaddress.ip_address(raw_ip)
    if not receiver.is_private or receiver.is_loopback or receiver.is_multicast:
        raise ValueError("Receiver must be a reachable private LAN/VPN IP, not loopback or multicast.")
    if not 1024 <= port <= 65535:
        raise ValueError("Receiver port must be between 1024 and 65535.")
    return str(receiver)


def listen(receiver_ip: str, port: int) -> None:
    receiver_ip = validate_private_receiver(receiver_ip, port)
    family = socket.AF_INET6 if ":" in receiver_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind((receiver_ip, port))
        print(f"Demo receiver listening on UDP {receiver_ip}:{port}")
        print(f"Waiting for the controlled {PACKET_COUNT}-datagram replay; Ctrl+C stops the listener.")
        received = 0
        while True:
            data, source = sock.recvfrom(2048)
            if data.startswith(b"NETINSIGHT-CONTROLLED-DEMO:"):
                received += 1
                print(f"Received demo datagram {received}/{PACKET_COUNT} from {source[0]}:{source[1]}")
    finally:
        sock.close()


def load_agent_id() -> str:
    agent_id_path = PROJECT_ROOT / "agent_id.txt"
    if not agent_id_path.exists():
        raise RuntimeError("No agent_id.txt found. Start and register this laptop's agent first.")
    agent_id = agent_id_path.read_text(encoding="utf-8").strip()
    if not agent_id:
        raise RuntimeError("agent_id.txt is empty. Start and register this laptop's agent first.")
    return agent_id


def write_event(event: dict) -> Path:
    event_path = PROJECT_ROOT / "demo_event.json"
    if event_path.exists():
        raise RuntimeError("A demo event marker already exists. Wait for the current demo or remove demo_event.json after confirming it is stale.")
    temporary_path = event_path.with_suffix(".json.tmp")
    temporary_path.write_text(json.dumps(event), encoding="utf-8")
    temporary_path.replace(event_path)
    return event_path


def remove_event_if_owned(event_path: Path, event_id: str) -> None:
    try:
        current = json.loads(event_path.read_text(encoding="utf-8"))
        if current.get("event_id") == event_id:
            event_path.unlink(missing_ok=True)
    except (OSError, json.JSONDecodeError):
        pass


def read_demo_status(server: str, agent_id: str, event_id: str) -> dict:
    response = requests.get(
        f"{server.rstrip('/')}/api/v1/agents/demo-status",
        params={"agent_id": agent_id, "event_id": event_id},
        headers=auth_headers(),
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def replay_existing_agent(server: str, receiver_ip: str, receiver_port: int) -> bool:
    receiver_ip = validate_private_receiver(receiver_ip, receiver_port)
    agent_id = load_agent_id()
    server = server.rstrip("/")
    status_url = f"{server}/api/v1/agents/demo-status"
    try:
        response = requests.get(
            status_url,
            params={"agent_id": agent_id, "event_id": str(uuid.uuid4())},
            headers=auth_headers(),
            timeout=5,
        )
        if response.status_code == 401:
            raise RuntimeError("Server requires NETINSIGHT_AGENT_TOKEN; set the matching token in this shell.")
        if response.status_code == 404:
            raise RuntimeError("This agent ID is not registered on the server. Start this laptop's agent first.")
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Cannot reach the NetInsight server at {server}: {exc}") from exc

    initial_status = response.json()
    if not initial_status.get("server_enforcement_enabled"):
        raise RuntimeError("Server flow enforcement is disabled. Enable NETINSIGHT_ENABLE_FLOW_ENFORCEMENT on the server.")
    if not initial_status.get("demo_enforcement_enabled"):
        raise RuntimeError("Demo flow enforcement is disabled. Enable NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT on the server.")
    if not initial_status.get("agent_enforcement_capable"):
        raise RuntimeError("The existing agent is not running the updated Windows firewall build as Administrator. Restart it with enforcement enabled.")

    source_ip = get_local_ip_for_receiver(receiver_ip, receiver_port)
    event_id = str(uuid.uuid4())
    event = {
        "event_id": event_id,
        "source_ip": source_ip,
        "receiver_ip": receiver_ip,
        "receiver_port": receiver_port,
        "expires_at": time.time() + DEMO_EVENT_LIFETIME_SECONDS,
    }
    event_path = write_event(event)
    sock = socket.socket(socket.AF_INET6 if ":" in receiver_ip else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((source_ip, 0))
        sock.connect((receiver_ip, receiver_port))
        source_port = sock.getsockname()[1]
        print("Existing-agent replay (no synthetic agent, no injected telemetry)")
        print(f"Agent ID: {agent_id}")
        print(f"Source: {source_ip}:{source_port}")
        print(f"Controlled receiver: {receiver_ip}:{receiver_port}")
        print(f"Sending exactly {PACKET_COUNT} small UDP datagrams at 2 packets/second.")
        print("Confirm the receiver is yours and listening before proceeding.")

        time.sleep(1.5)
        for index in range(PACKET_COUNT):
            payload = f"NETINSIGHT-CONTROLLED-DEMO:{event_id}:{index + 1}".encode("ascii")
            sock.send(payload)
            print(f"Sent paced demo datagram {index + 1}/{PACKET_COUNT}")
            if index + 1 < PACKET_COUNT:
                time.sleep(PACKET_INTERVAL_SECONDS)

        print("Waiting up to 45 seconds for the existing agent to upload captured packets and enforce the rule...")
        deadline = time.monotonic() + 45
        last_status = {}
        while time.monotonic() < deadline:
            try:
                last_status = read_demo_status(server, agent_id, event_id)
            except requests.RequestException as exc:
                print(f"Status check failed temporarily: {exc}")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            xgb_flows = last_status.get("xgboost_flows", [])
            matching_blocks = [
                rule for rule in last_status.get("active_flow_blocks", [])
                if rule.get("demo_event_id") == event_id
                and rule.get("dst_ip") == receiver_ip
                and int(rule.get("dst_port", 0)) == receiver_port
            ]
            if xgb_flows:
                best = max(xgb_flows, key=lambda flow: flow.get("confidence") or 0.0)
                print(
                    f"XGBoost evidence: {best['threat_label']} "
                    f"({(best.get('confidence') or 0.0) * 100:.1f}% confidence, "
                    f"{best['packet_count']} packets)."
                )
            if matching_blocks:
                print("SUCCESS: the existing agent acknowledged its exact outbound Windows Firewall rule.")
                print("Check the receiver: datagrams should stop arriving once the firewall rule is active.")
                return True
            if xgb_flows:
                print("XGBoost classified the flow; waiting for agent firewall acknowledgement...")
            time.sleep(POLL_INTERVAL_SECONDS)

        if last_status.get("xgboost_flows"):
            print("XGBoost classification was recorded, but no matching firewall acknowledgement arrived.")
            print("Check Administrator rights, agent opt-in, receiver IP, and Windows Firewall logs.")
        else:
            print("No XGBoost-confirmed flow was recorded before timeout; no block is claimed.")
            print("Check Npcap/interface selection and verify the running agent has the updated code.")
        return False
    finally:
        sock.close()
        remove_event_if_owned(event_path, event_id)


def get_local_ip_for_receiver(receiver_ip: str, receiver_port: int) -> str:
    with socket.socket(socket.AF_INET6 if ":" in receiver_ip else socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
        route_socket.connect((receiver_ip, receiver_port))
        return route_socket.getsockname()[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Controlled NetInsight demo: 40 tiny paced private UDP datagrams through an existing registered agent; no flood or fake agent."
    )
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--listen", action="store_true", help="Run the private UDP demo receiver on this laptop.")
    modes.add_argument("--agent-replay", action="store_true", help="Replay through this laptop's already-running registered agent.")
    parser.add_argument("--server", default="http://localhost:8000", help="NetInsight server URL for --agent-replay.")
    parser.add_argument("--receiver-ip", help="Private LAN/VPN IP of the receiver laptop you control.")
    parser.add_argument("--receiver-port", type=int, default=45678)
    parser.add_argument("--confirm", action="store_true", help="Confirm the receiver is yours and is listening.")
    args = parser.parse_args()

    if args.listen:
        if not args.receiver_ip:
            parser.error("--listen requires --receiver-ip set to this receiver laptop's private LAN/VPN IP")
        try:
            listen(args.receiver_ip, args.receiver_port)
        except (OSError, ValueError) as exc:
            print(f"Receiver error: {exc}", file=sys.stderr)
            return 2
        return 0

    if not args.confirm:
        parser.error("--agent-replay requires --confirm after you have started the receiver on a laptop you control")
    if not args.receiver_ip:
        parser.error("--agent-replay requires --receiver-ip")
    if not os.environ.get("NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", "False").lower() in {"true", "1", "yes"}:
        parser.error("Set NETINSIGHT_ENABLE_FLOW_ENFORCEMENT=True in this agent shell before replay")

    try:
        return 0 if replay_existing_agent(args.server, args.receiver_ip, args.receiver_port) else 1
    except (OSError, ValueError, RuntimeError, requests.RequestException) as exc:
        print(f"Demo aborted safely: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
