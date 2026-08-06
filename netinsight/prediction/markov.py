import logging

import numpy as np

from netinsight.config import settings

logger = logging.getLogger(__name__)

class MarkovPredictor:
    """Estimates transition probability matrices and predicts future network states."""

    # Map standard 5 title-case state names to indexes for matrix operations
    STATE_INDEX = {
        "Normal": 0,
        "Busy": 1,
        "Congested": 2,
        "Under Attack": 3,
        "Recovering": 4
    }
    INDEX_STATE = {v: k for k, v in STATE_INDEX.items()}

    def __init__(self):
        # Default 5x5 transition matrix matching HiddenMarkovModel prior probabilities
        self.default_transition_matrix = np.array([
            [0.75, 0.15, 0.05, 0.03, 0.02],  # Normal
            [0.20, 0.60, 0.15, 0.03, 0.02],  # Busy
            [0.05, 0.20, 0.55, 0.05, 0.15],  # Congested
            [0.02, 0.03, 0.10, 0.70, 0.15],  # Under Attack
            [0.30, 0.10, 0.05, 0.05, 0.50]   # Recovering
        ])

    def classify_state(self, util: float, loss: float, threat_label: str = "Normal") -> str:
        """Classifies metrics into standard network states using settings.py thresholds."""
        if threat_label in ["DoS", "DDoS", "Mirai"]:
            return "Under Attack"

        thresholds = settings.STATE_THRESHOLDS

        if util >= thresholds["FAILURE"]["util_min"] or loss >= thresholds["FAILURE"]["loss_min"]:
            return "Under Attack"
        if thresholds["CONGESTED"]["util_min"] <= util < thresholds["CONGESTED"]["util_max"] or loss >= thresholds["CONGESTED"]["loss_max"]:
            return "Congested"
        if thresholds["BUSY"]["util_min"] <= util < thresholds["BUSY"]["util_max"] or loss >= thresholds["BUSY"]["loss_max"]:
            return "Busy"
        return "Normal"

    def _canonicalize_state(self, s: str) -> str:
        """Normalizes free-text database state string to canonical 5 title-case states."""
        if not s:
            return "Normal"
        s_upper = s.strip().upper()
        mapping = {
            "NORMAL": "Normal",
            "BUSY": "Busy",
            "CONGESTED": "Congested",
            "FAILURE": "Under Attack",
            "UNDER ATTACK": "Under Attack",
            "RECOVERING": "Recovering"
        }
        return mapping.get(s_upper, "Normal")

    def _estimate_transition_matrix(self) -> tuple[np.ndarray, bool]:
        """Internal implementation that also reports whether the default matrix was used."""
        try:
            from netinsight.dashboard.models import StateHistory
            raw_states = list(StateHistory.objects.order_by("timestamp").values_list("network_state", flat=True))

            if len(raw_states) < 2:
                logger.info("Insufficient state history to estimate Markov transition matrix. Using default transitions.")
                return self.default_transition_matrix, True

            states = [self._canonicalize_state(s) for s in raw_states]

            # Count transitions across 5 states
            counts = np.zeros((5, 5))
            for i in range(len(states) - 1):
                s_curr = states[i]
                s_next = states[i + 1]

                if s_curr in self.STATE_INDEX and s_next in self.STATE_INDEX:
                    idx_curr = self.STATE_INDEX[s_curr]
                    idx_next = self.STATE_INDEX[s_next]
                    counts[idx_curr, idx_next] += 1

            # Normalize to create 5x5 row-stochastic matrix
            transition_matrix = np.zeros((5, 5))
            for i in range(5):
                row_sum = counts[i].sum()
                if row_sum > 0:
                    transition_matrix[i] = counts[i] / row_sum
                else:
                    transition_matrix[i] = self.default_transition_matrix[i]

            return transition_matrix, False
        except Exception as e:
            logger.debug(f"Using default Markov transition matrix fallback: {e}")
            return self.default_transition_matrix, True

    def estimate_transition_matrix(self) -> np.ndarray:
        """Retrieves history from state_history table and computes the transition matrix.

        Formula:
            P_ij = N_ij / sum_k(N_ik)
        Returns:
            np.ndarray: A 4x4 row-stochastic matrix.
        """
        return self._estimate_transition_matrix()[0]

    def predict_state_distribution(self, current_state: str, k_steps: int = 1) -> dict:
        """Predicts the probability distribution of states k steps into the future.

        Formula:
            s^(t+k) = s^(t) * P^k
        """
        current_state = self._canonicalize_state(current_state)
        if current_state not in self.STATE_INDEX:
            current_state = "Normal"

        # One-hot 5-state vector
        s_t = np.zeros(5)
        s_t[self.STATE_INDEX[current_state]] = 1.0

        P, using_default = self._estimate_transition_matrix()

        # P^k
        P_k = np.linalg.matrix_power(P, k_steps)

        s_future = s_t @ P_k

        return {
            "matrix": P.tolist(),
            "prediction": {self.INDEX_STATE[i]: float(s_future[i]) for i in range(5)},
            "most_likely": self.INDEX_STATE[int(np.argmax(s_future))],
            "using_default_matrix": using_default,
        }
