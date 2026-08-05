import logging
import math
import time

import numpy as np

from netinsight.dashboard.models import StateHistory

logger = logging.getLogger(__name__)

# Hidden States mapping
HIDDEN_STATES = {
    0: "Normal",
    1: "Busy",
    2: "Congested",
    3: "Under Attack",
    4: "Recovering"
}
STATE_INDEX = {v: k for k, v in HIDDEN_STATES.items()}

# XGBoost Threat Labels mapping
THREAT_LABELS = {
    "Normal": 0,
    "DoS": 1,
    "DDoS": 2,
    "Brute Force": 3,
    "Reconnaissance": 4,
    "Mirai": 5,
    "Other Attacks": 6
}

class HiddenMarkovModel:
    """Manages Hidden Markov Model state predictions, emissions, and Viterbi decoding."""

    def __init__(self):
        # 1. State Transition Matrix A (shape: 5x5)
        # A[i, j] represents P(State_j | State_i)
        self.transition_matrix = np.array([
            [0.75, 0.15, 0.05, 0.03, 0.02],  # Normal ->
            [0.20, 0.60, 0.15, 0.03, 0.02],  # Busy ->
            [0.05, 0.20, 0.55, 0.05, 0.15],  # Congested ->
            [0.02, 0.03, 0.10, 0.70, 0.15],  # Under Attack ->
            [0.30, 0.10, 0.05, 0.05, 0.50]   # Recovering ->
        ])

        # 2. Discrete Threat Emission Matrix for XGBoost Labels (shape: 5x7)
        # Rows: Hidden States, Columns: XGBoost Threat Labels
        self.threat_emission = np.array([
            [0.95, 0.01, 0.00, 0.01, 0.01, 0.01, 0.01],  # Normal expects Normal
            [0.90, 0.02, 0.00, 0.02, 0.02, 0.02, 0.02],  # Busy expects Normal
            [0.85, 0.03, 0.01, 0.03, 0.03, 0.02, 0.03],  # Congested expects Normal
            [0.05, 0.25, 0.35, 0.15, 0.10, 0.05, 0.05],  # Under Attack expects Attacks
            [0.80, 0.05, 0.02, 0.03, 0.03, 0.02, 0.05]   # Recovering expects Normal
        ])

        # 3. Continuous Emission Parameters (Gaussian Means & Std Devs for each State)
        # Features: [Utilization (%), Latency (s), Loss (%), Packet Rate (pps), Sockets]
        self.gaussian_params = {
            "Normal": {
                "util": (15.0, 8.0),
                "latency": (0.012, 0.005),
                "loss": (0.1, 0.2),
                "packet_rate": (10.0, 5.0),
                "sockets": (5.0, 2.0)
            },
            "Busy": {
                "util": (55.0, 12.0),
                "latency": (0.045, 0.015),
                "loss": (1.2, 0.8),
                "packet_rate": (60.0, 20.0),
                "sockets": (25.0, 10.0)
            },
            "Congested": {
                "util": (85.0, 10.0),
                "latency": (0.150, 0.050),
                "loss": (6.5, 2.5),
                "packet_rate": (150.0, 45.0),
                "sockets": (70.0, 20.0)
            },
            "Under Attack": {
                "util": (75.0, 25.0),
                "latency": (0.280, 0.110),
                "loss": (12.0, 5.0),
                "packet_rate": (850.0, 300.0),
                "sockets": (120.0, 40.0)
            },
            "Recovering": {
                "util": (30.0, 12.0),
                "latency": (0.080, 0.030),
                "loss": (2.0, 1.5),
                "packet_rate": (35.0, 15.0),
                "sockets": (20.0, 8.0)
            }
        }

        # TTL cache for transition matrix (avoids DB query on every telemetry POST)
        self._cached_transition_matrix = None
        self._transition_cache_time = 0.0
        self._transition_cache_ttl = 60.0  # seconds

    def _calculate_log_gaussian_pdf(self, val: float, mean: float, std: float) -> float:
        """Calculates log of univariate Gaussian PDF for numerical stability.

        log N(x|μ,σ) = -0.5*log(2π) - log(σ) - (x-μ)²/(2σ²)
        """
        if std <= 0:
            std = 1e-4
        return -0.5 * math.log(2 * math.pi) - math.log(std) - ((val - mean) ** 2) / (2 * (std ** 2))

    def calculate_log_emission_probability(self, state_name: str, observation: dict) -> float:
        """Computes log emission probability log P(Observation | State) using log-space arithmetic.

        Uses log-space to prevent numerical underflow from multiplying small PDF values
        and to eliminate feature scale bias (latency σ=0.005 vs packet_rate σ=300).
        """
        try:
            params = self.gaussian_params[state_name]

            # Continuous metrics scores in log-space (sum of logs = log of product)
            log_p_util = self._calculate_log_gaussian_pdf(observation["util"], *params["util"])
            log_p_latency = self._calculate_log_gaussian_pdf(observation["latency"], *params["latency"])
            log_p_loss = self._calculate_log_gaussian_pdf(observation["loss"], *params["loss"])
            log_p_rate = self._calculate_log_gaussian_pdf(observation["packet_rate"], *params["packet_rate"])
            log_p_sockets = self._calculate_log_gaussian_pdf(observation["sockets"], *params["sockets"])

            # Sum of log-probabilities (equivalent to log of product)
            log_p_continuous = log_p_util + log_p_latency + log_p_loss + log_p_rate + log_p_sockets

            # Discrete Threat label score from XGBoost
            threat_name = observation.get("threat_label", "Normal")
            threat_idx = THREAT_LABELS.get(threat_name, 0)
            state_idx = STATE_INDEX[state_name]
            p_discrete = self.threat_emission[state_idx, threat_idx]

            # Joint log emission probability
            log_p_discrete = math.log(max(1e-15, p_discrete))
            return log_p_continuous + log_p_discrete
        except Exception as e:
            logger.error(f"Error computing emission probability for {state_name}: {e}")
            return math.log(1e-15)

    def estimate_transition_matrix(self) -> np.ndarray:
        """Estimates transitions between hidden states dynamically from StateHistory database."""
        # Return cached matrix if still within TTL
        if self._cached_transition_matrix is not None and (time.time() - self._transition_cache_time) < self._transition_cache_ttl:
            return self._cached_transition_matrix

        try:
            # Query only the latest 300 state histories chronologically
            history = list(StateHistory.objects.all().order_by("-timestamp")[:300])[::-1]
            states = [r.network_state for r in history]

            if len(states) < 2:
                return self.transition_matrix

            counts = np.zeros((5, 5))
            for i in range(len(states) - 1):
                s_curr = states[i]
                s_next = states[i+1]
                if s_curr in STATE_INDEX and s_next in STATE_INDEX:
                    counts[STATE_INDEX[s_curr], STATE_INDEX[s_next]] += 1

            # Row-stochastic normalization
            P = np.copy(self.transition_matrix)
            for i in range(5):
                row_sum = counts[i].sum()
                if row_sum > 0:
                    # Blend empirical transitions with prior transition probabilities
                    empirical = counts[i] / row_sum
                    P[i] = 0.4 * self.transition_matrix[i] + 0.6 * empirical

            self._cached_transition_matrix = P
            self._transition_cache_time = time.time()
            return P
        except Exception as e:
            logger.error(f"Error estimating HMM transitions: {e}")
            return self.transition_matrix

    def decode_states(self, observations_list: list[dict]) -> list[str]:
        """Runs the Viterbi Algorithm in log-probability space for numerical stability.

        Log-space Viterbi DP Updates:
            log V_t(j) = max_i [ log V_{t-1}(i) + log A_ij + log B_j(o_t) ]
        """
        N = len(HIDDEN_STATES)
        T = len(observations_list)

        if T == 0:
            return []

        # Prior probabilities (uniform distribution over states)
        pi = np.array([0.40, 0.20, 0.15, 0.10, 0.15])

        # Viterbi DP tables in LOG-SPACE
        viterbi_table = np.full((N, T), -np.inf)
        backpointer = np.zeros((N, T), dtype=int)

        # Step 1. Initialization (log-space)
        obs_0 = observations_list[0]
        for s in range(N):
            state_name = HIDDEN_STATES[s]
            log_emission = self.calculate_log_emission_probability(state_name, obs_0)
            viterbi_table[s, 0] = math.log(max(1e-15, pi[s])) + log_emission
            backpointer[s, 0] = 0

        # Dynamic transition matrix estimation
        A = self.estimate_transition_matrix()
        # Pre-compute log transition matrix
        log_A = np.log(np.maximum(A, 1e-15))

        # Step 2. Recursion (log-space: addition replaces multiplication)
        for t in range(1, T):
            obs_t = observations_list[t]
            for s in range(N):
                state_name = HIDDEN_STATES[s]
                log_emission = self.calculate_log_emission_probability(state_name, obs_t)

                # Find max transition path in log-space
                log_probs = [viterbi_table[prev_s, t-1] + log_A[prev_s, s] + log_emission for prev_s in range(N)]
                viterbi_table[s, t] = max(log_probs)
                backpointer[s, t] = int(np.argmax(log_probs))

        # Step 3. Termination & Backtracking
        best_path = []
        best_last_state = int(np.argmax(viterbi_table[:, T-1]))
        best_path.append(best_last_state)

        for t in range(T-1, 0, -1):
            curr_state = best_path[-1]
            prev_state = int(backpointer[curr_state, t])
            best_path.append(prev_state)

        # Map state indexes to names
        decoded_path = [HIDDEN_STATES[idx] for idx in reversed(best_path)]
        return decoded_path

    def predict_state_forecast(self, current_state_name: str, steps: int = 1) -> dict:
        """Forecasts state probabilities k steps into the future."""
        if current_state_name not in STATE_INDEX:
            current_state_name = "Normal"

        state_idx = STATE_INDEX[current_state_name]

        # One-hot state vector
        s_t = np.zeros(5)
        s_t[state_idx] = 1.0

        A = self.estimate_transition_matrix()
        A_power = np.linalg.matrix_power(A, steps)

        s_forecast = s_t @ A_power

        return {
            "forecast": {HIDDEN_STATES[i]: float(s_forecast[i]) for i in range(5)},
            "most_likely": HIDDEN_STATES[int(np.argmax(s_forecast))]
        }
