import logging

import numpy as np
import pandas as pd

from netinsight.config import settings
from netinsight.database import db_manager

logger = logging.getLogger(__name__)

class MarkovPredictor:
    """Estimates transition probability matrices and predicts future network states."""

    # Map state names to indexes for mathematical matrix operations
    STATE_INDEX = {
        "NORMAL": 0,
        "BUSY": 1,
        "CONGESTED": 2,
        "FAILURE": 3
    }
    INDEX_STATE = {v: k for k, v in STATE_INDEX.items()}

    def __init__(self):
        # Default uniform matrix used when history is insufficient
        self.default_transition_matrix = np.array([
            [0.70, 0.20, 0.08, 0.02],  # Normal
            [0.15, 0.65, 0.15, 0.05],  # Busy
            [0.05, 0.20, 0.60, 0.15],  # Congested
            [0.02, 0.08, 0.20, 0.70]   # Failure
        ])

    def classify_state(self, util: float, loss: float) -> str:
        """Classifies metrics into network states dynamically using settings.py."""
        thresholds = settings.STATE_THRESHOLDS

        if util >= thresholds["FAILURE"]["util_min"] or loss >= thresholds["FAILURE"]["loss_min"]:
            return "FAILURE"
        if thresholds["CONGESTED"]["util_min"] <= util < thresholds["CONGESTED"]["util_max"]:
            return "CONGESTED"
        if thresholds["BUSY"]["util_min"] <= util < thresholds["BUSY"]["util_max"]:
            return "BUSY"
        return "NORMAL"

    def _estimate_transition_matrix(self) -> tuple[np.ndarray, bool]:
        """Internal implementation that also reports whether the default matrix was used."""
        conn = db_manager.get_connection()
        try:
            df = pd.read_sql_query(
                "SELECT network_state FROM state_history ORDER BY timestamp ASC",
                conn
            )

            if len(df) < 2:
                logger.info("Insufficient state history to estimate Markov transition matrix. Using default transitions.")
                return self.default_transition_matrix, True

            states = df["network_state"].tolist()

            # Count transitions
            counts = np.zeros((4, 4))
            for i in range(len(states) - 1):
                s_curr = states[i]
                s_next = states[i+1]

                if s_curr in self.STATE_INDEX and s_next in self.STATE_INDEX:
                    idx_curr = self.STATE_INDEX[s_curr]
                    idx_next = self.STATE_INDEX[s_next]
                    counts[idx_curr, idx_next] += 1

            # Normalize to create row-stochastic matrix (transition probabilities)
            transition_matrix = np.zeros((4, 4))
            for i in range(4):
                row_sum = counts[i].sum()
                if row_sum > 0:
                    transition_matrix[i] = counts[i] / row_sum
                else:
                    # Fallback to default transitions for states with no observed departures
                    transition_matrix[i] = self.default_transition_matrix[i]

            return transition_matrix, False

        except Exception as e:
            logger.error(f"Error estimating Markov transition matrix: {e}", exc_info=True)
            return self.default_transition_matrix, True
        finally:
            conn.close()

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
        if current_state not in self.STATE_INDEX:
            current_state = "NORMAL"

        # One-hot state vector
        s_t = np.zeros(4)
        s_t[self.STATE_INDEX[current_state]] = 1.0

        P, using_default = self._estimate_transition_matrix()

        # P^k
        P_k = np.linalg.matrix_power(P, k_steps)

        s_future = s_t @ P_k

        return {
            "matrix": P.tolist(),
            "prediction": {self.INDEX_STATE[i]: float(s_future[i]) for i in range(4)},
            "most_likely": self.INDEX_STATE[int(np.argmax(s_future))],
            "using_default_matrix": using_default,
        }
