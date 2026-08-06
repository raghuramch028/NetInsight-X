"""Centralized dictionary definitions for traffic classes, threat types, and HMM hidden states."""

CLASS_LABELS = {
    0: "Normal",
    1: "DoS",
    2: "DDoS",
    3: "Brute Force",
    4: "Reconnaissance",
    5: "Mirai",
    6: "Other Attacks"
}

THREAT_LABELS = CLASS_LABELS

HIDDEN_STATES = {
    0: "Normal",
    1: "Busy",
    2: "Congested",
    3: "Under Attack",
    4: "Recovering"
}
STATE_INDEX = {v: k for k, v in HIDDEN_STATES.items()}
