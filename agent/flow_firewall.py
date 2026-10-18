"""Opt-in Windows Firewall enforcement for classified outbound flows."""

import hashlib
import ipaddress
import json
import platform
import subprocess
import threading
import time

from agent.logger import logger

_RULE_PREFIX = "NetInsightFlowBlock-"


class WindowsFlowFirewall:
    """Reconciles short-lived outbound Windows Firewall rules for one local agent."""

    def __init__(self, enabled: bool, local_ip: str, ttl_seconds: int = 120):
        self.enabled = bool(enabled)
        self.local_ip = local_ip
        self.ttl_seconds = max(30, min(300, int(ttl_seconds)))
        self._active: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread = None

        if platform.system() != "Windows":
            self.enabled = False
            return

        self._remove_stale_owned_rules()
        if not self.enabled:
            logger.info("[FLOW FIREWALL] Disabled; stale NetInsight-owned rules cleared. Set NETINSIGHT_ENABLE_FLOW_ENFORCEMENT=true to opt in.")
            return
        self._thread = threading.Thread(target=self._expiry_loop, name="flow-firewall-expiry", daemon=True)
        self._thread.start()
        logger.warning(
            "[FLOW FIREWALL] Outbound flow blocking enabled. Run this agent as Administrator; "
            f"rules expire after {self.ttl_seconds}s and are cleared on normal shutdown."
        )

    @staticmethod
    def _rule_name(rule: dict) -> str | None:
        try:
            source_ip = str(ipaddress.ip_address(rule["src_ip"]))
            destination_ip = str(ipaddress.ip_address(rule["dst_ip"]))
            protocol = str(rule["protocol"]).upper()
            source_port = int(rule["src_port"])
            destination_port = int(rule["dst_port"])
            if protocol not in {"TCP", "UDP"}:
                return None
            if not 1 <= source_port <= 65535 or not 1 <= destination_port <= 65535:
                return None
            canonical = json.dumps(
                [source_ip, source_port, destination_ip, destination_port, protocol],
                separators=(",", ":"),
            )
            digest = hashlib.sha256(canonical.encode("ascii")).hexdigest()[:24]
            return f"{_RULE_PREFIX}{digest}"
        except (KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def _run_powershell(script: str) -> None:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def _remove_stale_owned_rules(self) -> None:
        script = (
            "$rules = Get-NetFirewallRule -Name 'NetInsightFlowBlock-*' "
            "-ErrorAction SilentlyContinue; "
            "if ($rules) { $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }"
        )
        try:
            self._run_powershell(script)
        except Exception as exc:
            logger.warning(f"[FLOW FIREWALL] Could not clear stale NetInsight rules: {exc}")

    def _install_rule(self, rule: dict, rule_name: str) -> None:
        source_ip = str(ipaddress.ip_address(rule["src_ip"]))
        destination_ip = str(ipaddress.ip_address(rule["dst_ip"]))
        protocol = str(rule["protocol"]).upper()
        source_port = int(rule["src_port"])
        destination_port = int(rule["dst_port"])
        display_name = "NetInsight outbound suspicious-flow block"
        script = (
            f"$existing = Get-NetFirewallRule -Name '{rule_name}' -ErrorAction SilentlyContinue; "
            "if (-not $existing) { "
            f"New-NetFirewallRule -Name '{rule_name}' -DisplayName '{display_name}' "
            f"-Direction Outbound -Action Block -Enabled True -Profile Any -Protocol {protocol} "
            f"-LocalAddress '{source_ip}' -LocalPort {source_port} "
            f"-RemoteAddress '{destination_ip}' -RemotePort {destination_port} "
            "-ErrorAction Stop | Out-Null }"
        )
        self._run_powershell(script)

    def _remove_rule(self, rule_name: str) -> None:
        script = (
            f"$rule = Get-NetFirewallRule -Name '{rule_name}' -ErrorAction SilentlyContinue; "
            "if ($rule) { $rule | Remove-NetFirewallRule -ErrorAction Stop }"
        )
        try:
            self._run_powershell(script)
        except Exception as exc:
            logger.warning(f"[FLOW FIREWALL] Could not remove rule {rule_name}: {exc}")

    def sync(self, rules: list[dict] | None) -> list[dict]:
        """Install current exact-flow rules, remove obsolete ones, and return acknowledgements."""
        if not self.enabled:
            return []

        desired: dict[str, dict] = {}
        for rule in rules or []:
            name = self._rule_name(rule)
            if not name:
                continue
            try:
                source_ip = str(ipaddress.ip_address(rule["src_ip"]))
                if source_ip != str(ipaddress.ip_address(self.local_ip)):
                    logger.warning("[FLOW FIREWALL] Ignoring a restriction not sourced by this agent host.")
                    continue
                destination_ip = str(ipaddress.ip_address(rule["dst_ip"]))
                desired[name] = {
                    "rule_name": name,
                    "src_ip": source_ip,
                    "src_port": int(rule["src_port"]),
                    "dst_ip": destination_ip,
                    "dst_port": int(rule["dst_port"]),
                    "protocol": str(rule["protocol"]).upper(),
                    "threat_label": str(rule.get("threat_label", "Threat"))[:100],
                    "demo_event_id": str(rule["demo_event_id"])[:64] if rule.get("demo_event_id") else None,
                }
            except (KeyError, TypeError, ValueError):
                continue

        with self._lock:
            existing_names = set(self._active)

        for name in existing_names - set(desired):
            self._remove_rule(name)
            with self._lock:
                self._active.pop(name, None)

        acknowledged = []
        for name, rule in desired.items():
            try:
                self._install_rule(rule, name)
                with self._lock:
                    self._active[name] = {
                        **rule,
                        "expires_at": time.monotonic() + self.ttl_seconds,
                    }
                acknowledged.append({key: value for key, value in rule.items() if key != "rule_name"})
            except Exception as exc:
                logger.error(
                    f"[FLOW FIREWALL] Failed to install {rule['protocol']} outbound block "
                    f"to {rule['dst_ip']}:{rule['dst_port']}: {exc}. Run the agent as Administrator."
                )
        return acknowledged

    def active_rules(self) -> list[dict]:
        with self._lock:
            return [
                {key: value for key, value in rule.items() if key not in {"rule_name", "expires_at"}}
                for rule in self._active.values()
            ]

    def _expiry_loop(self) -> None:
        while not self._stopped.wait(5):
            now = time.monotonic()
            with self._lock:
                expired = [
                    name for name, rule in self._active.items()
                    if rule["expires_at"] <= now
                ]
            for name in expired:
                self._remove_rule(name)
                with self._lock:
                    self._active.pop(name, None)

    def stop(self) -> None:
        self._stopped.set()
        with self._lock:
            names = list(self._active)
        for name in names:
            self._remove_rule(name)
        with self._lock:
            self._active.clear()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
