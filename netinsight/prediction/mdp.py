import logging
import numpy as np
from netinsight.config import settings

logger = logging.getLogger(__name__)

class MDPRecommendationEngine:
    """Solves a Markov Decision Process to recommend advisory administrative actions.

    States (S):
        0 = Normal, 1 = Busy, 2 = Congested, 3 = Under Attack, 4 = Recovering
    Actions (A):
        0 = Reallocate Bandwidth
        1 = Reroute Traffic
        2 = Prioritize Critical Services
    """

    ACTION_NAMES = {
        0: "Reallocate Bandwidth",
        1: "Reroute Traffic",
        2: "Prioritize Critical Services"
    }

    STATE_MAP = {
        "NORMAL": 0,
        "BUSY": 1,
        "CONGESTED": 2,
        "UNDER ATTACK": 3,
        "RECOVERING": 4
    }

    def __init__(self):
        # Discount factor gamma
        self.gamma = getattr(settings, "MDP_DISCOUNT_FACTOR", 0.90)

        # Transition matrices P_a (shape: 5x5) for each action:
        # P[s, s'] represents P(s' | s, a)

        # Action 0: Reallocate Bandwidth (highly effective in Normal/Busy; ineffective under attack)
        self.P_reallocate = np.array([
            [0.85, 0.10, 0.03, 0.01, 0.01],  # Normal
            [0.55, 0.35, 0.06, 0.02, 0.02],  # Busy
            [0.20, 0.50, 0.20, 0.05, 0.05],  # Congested
            [0.02, 0.03, 0.15, 0.75, 0.05],  # Under Attack
            [0.45, 0.35, 0.10, 0.02, 0.08]   # Recovering
        ])

        # Action 1: Reroute Traffic (heavy impact, exits Congested/Under Attack)
        self.P_reroute = np.array([
            [0.70, 0.20, 0.06, 0.02, 0.02],  # Normal
            [0.45, 0.40, 0.08, 0.03, 0.04],  # Busy
            [0.60, 0.25, 0.08, 0.02, 0.05],  # Congested
            [0.35, 0.25, 0.15, 0.10, 0.15],  # Under Attack
            [0.50, 0.25, 0.10, 0.05, 0.10]   # Recovering
        ])

        # Action 2: Prioritize Critical Services (mitigates Under Attack state impact, stable)
        self.P_prioritize = np.array([
            [0.80, 0.12, 0.05, 0.01, 0.02],  # Normal
            [0.45, 0.40, 0.08, 0.02, 0.05],  # Busy
            [0.30, 0.40, 0.20, 0.04, 0.06],  # Congested
            [0.25, 0.35, 0.15, 0.05, 0.20],  # Under Attack
            [0.40, 0.30, 0.10, 0.05, 0.15]   # Recovering
        ])

        self.P_matrices = {
            0: self.P_reallocate,
            1: self.P_reroute,
            2: self.P_prioritize
        }

        # Fallback rewards matrix (5 states x 3 actions)
        self.default_rewards = {
            0: {0: 10.0, 1: 5.0, 2: 8.0},    # Normal (likes Reallocation)
            1: {0: 8.0,  1: 4.0, 2: 7.0},    # Busy (likes Reallocation)
            2: {0: 4.0,  1: 9.0, 2: 6.0},    # Congested (likes Reroute)
            3: {0: -5.0, 1: 2.0, 2: 10.0},   # Under Attack (likes Prioritization)
            4: {0: 7.0,  1: 4.0, 2: 8.0}     # Recovering (likes Reallocation/Prioritize)
        }

    def get_reward(self, state: int, action: int) -> float:
        """Returns the reward value for the given state-action pair."""
        # Use settings.MDP_REWARDS if configured and matches 5-state keys
        try:
            rewards = getattr(settings, "MDP_REWARDS", {})
            if state in rewards and action in rewards[state]:
                return float(rewards[state][action])
        except Exception:
            pass
        return float(self.default_rewards[state][action])

    def solve_value_iteration(self, tolerance: float = 1e-6, max_iter: int = 1000) -> tuple[np.ndarray, np.ndarray]:
        """Runs the MDP Value Iteration algorithm to find the optimal Value and Policy.

        Bellman Optimality Equation:
            V^(k+1)(s) = max_a [ R(s, a) + gamma * sum_s' P(s'|s, a) * V^(k)(s') ]
        """
        V = np.zeros(5)
        policy = np.zeros(5, dtype=int)

        for _iteration in range(max_iter):
            V_new = np.copy(V)
            delta = 0.0

            for s in range(5):
                action_values = []
                for a in range(3):
                    r = self.get_reward(s, a)
                    transition_sum = sum(self.P_matrices[a][s, s_prime] * V[s_prime] for s_prime in range(5))
                    val = r + self.gamma * transition_sum
                    action_values.append(val)

                # Update value function
                V_new[s] = max(action_values)
                delta = max(delta, abs(V_new[s] - V[s]))

            V = V_new
            if delta < tolerance:
                break

        # Compute the optimal policy based on converged values
        for s in range(5):
            action_values = []
            for a in range(3):
                r = self.get_reward(s, a)
                transition_sum = sum(self.P_matrices[a][s, s_prime] * V[s_prime] for s_prime in range(5))
                val = r + self.gamma * transition_sum
                action_values.append(val)
            policy[s] = int(np.argmax(action_values))

        return V, policy

    def get_recommendation(self, current_state_name: str) -> dict:
        """Solves the MDP policy and returns the advisory action for the current state."""
        state_idx = self.STATE_MAP.get(current_state_name.upper(), 0)

        V, policy = self.solve_value_iteration()
        opt_action_idx = int(policy[state_idx])
        recommended_action = self.ACTION_NAMES[opt_action_idx]

        # Calculate expected values for each action at the current state to display in dashboard
        action_values = {}
        for a in range(3):
            r = self.get_reward(state_idx, a)
            transition_sum = sum(self.P_matrices[a][state_idx, s_prime] * V[s_prime] for s_prime in range(5))
            expected_val = r + self.gamma * transition_sum
            action_values[self.ACTION_NAMES[a]] = float(expected_val)

        logger.info(f"MDP recommendation solved. Current State={current_state_name}, Recommended Action={recommended_action}")
        
        # Build human-readable mapping of the policy
        reverse_map = {0: "Normal", 1: "Busy", 2: "Congested", 3: "Under Attack", 4: "Recovering"}
        policy_map = {reverse_map[idx]: self.ACTION_NAMES[policy[idx]] for idx in range(5)}

        return {
            "current_state": current_state_name,
            "recommended_action": recommended_action,
            "action_values": action_values,
            "optimal_policy": policy_map
        }
