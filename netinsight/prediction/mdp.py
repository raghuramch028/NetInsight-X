import logging
import numpy as np
from netinsight.config import settings

logger = logging.getLogger(__name__)

class MDPRecommendationEngine:
    """Solves a Markov Decision Process to recommend advisory administrative actions.
    
    States (S):
        0 = NORMAL, 1 = BUSY, 2 = CONGESTED, 3 = FAILURE
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

    def __init__(self):
        # Discount factor gamma from settings
        self.gamma = settings.MDP_DISCOUNT_FACTOR
        
        # State Transition Matrices for each Action P_a (size: 4x4)
        # P_a[s, s'] represents transition from s to s' under action a.
        
        # Action 0: Reallocate Bandwidth (highly effective in normal/busy states)
        self.P_reallocate = np.array([
            [0.85, 0.10, 0.04, 0.01],
            [0.50, 0.40, 0.08, 0.02],
            [0.20, 0.50, 0.25, 0.05],
            [0.05, 0.15, 0.40, 0.40]
        ])
        
        # Action 1: Reroute Traffic (heavy impact, useful to exit congested/failure states)
        self.P_reroute = np.array([
            [0.70, 0.20, 0.08, 0.02],
            [0.40, 0.50, 0.08, 0.02],
            [0.60, 0.25, 0.12, 0.03],
            [0.30, 0.40, 0.20, 0.10]
        ])
        
        # Action 2: Prioritize Critical Services (mitigates failure state impact, stable)
        self.P_prioritize = np.array([
            [0.80, 0.12, 0.06, 0.02],
            [0.45, 0.45, 0.08, 0.02],
            [0.30, 0.40, 0.25, 0.05],
            [0.25, 0.35, 0.30, 0.10]
        ])
        
        self.P_matrices = {
            0: self.P_reallocate,
            1: self.P_reroute,
            2: self.P_prioritize
        }

    def get_reward(self, state: int, action: int) -> float:
        """Returns the configurable reward value for the given state-action pair."""
        try:
            return float(settings.MDP_REWARDS[state][action])
        except (KeyError, TypeError):
            # Fallback rewards if settings is corrupt or missing
            fallbacks = {
                0: {0: 10.0, 1: 5.0, 2: 8.0},
                1: {0: 8.0,  1: 4.0, 2: 7.0},
                2: {0: 5.0,  1: 8.0, 2: 6.0},
                3: {0: -2.0, 1: -5.0, 2: 2.0}
            }
            return float(fallbacks[state][action])

    def solve_value_iteration(self, tolerance: float = 1e-6, max_iter: int = 1000) -> tuple[np.ndarray, np.ndarray]:
        """Runs the MDP Value Iteration algorithm to find the optimal Value and Policy.
        
        Bellman Optimality Update:
            V^(k+1)(s) = max_a [ R(s, a) + gamma * sum_s' P_a(s'|s) * V^(k)(s') ]
        """
        V = np.zeros(4)
        policy = np.zeros(4, dtype=int)
        
        for iteration in range(max_iter):
            V_new = np.copy(V)
            delta = 0.0
            
            for s in range(4):
                action_values = []
                for a in range(3):
                    r = self.get_reward(s, a)
                    transition_sum = sum(self.P_matrices[a][s, s_prime] * V[s_prime] for s_prime in range(4))
                    val = r + self.gamma * transition_sum
                    action_values.append(val)
                    
                # Update value function
                V_new[s] = max(action_values)
                delta = max(delta, abs(V_new[s] - V[s]))
                
            V = V_new
            if delta < tolerance:
                break
                
        # Compute the optimal policy based on converged values
        for s in range(4):
            action_values = []
            for a in range(3):
                r = self.get_reward(s, a)
                transition_sum = sum(self.P_matrices[a][s, s_prime] * V[s_prime] for s_prime in range(4))
                val = r + self.gamma * transition_sum
                action_values.append(val)
            policy[s] = int(np.argmax(action_values))
            
        return V, policy

    def get_recommendation(self, current_state_name: str) -> dict:
        """Solves the MDP policy and returns the advisory action for the current state."""
        state_map = {"NORMAL": 0, "BUSY": 1, "CONGESTED": 2, "FAILURE": 3}
        state_idx = state_map.get(current_state_name.upper(), 0)
        
        V, policy = self.solve_value_iteration()
        opt_action_idx = int(policy[state_idx])
        recommended_action = self.ACTION_NAMES[opt_action_idx]
        
        # Calculate expected values for each action at the current state to display in dashboard
        action_values = {}
        for a in range(3):
            r = self.get_reward(state_idx, a)
            transition_sum = sum(self.P_matrices[a][state_idx, s_prime] * V[s_prime] for s_prime in range(4))
            expected_val = r + self.gamma * transition_sum
            action_values[self.ACTION_NAMES[a]] = float(expected_val)
            
        logger.info(f"MDP recommendation solved. Current State={current_state_name}, Recommended Action={recommended_action}")
        return {
            "current_state": current_state_name,
            "recommended_action": recommended_action,
            "action_values": action_values,
            "optimal_policy": {state_map_key: self.ACTION_NAMES[policy[idx]] for state_map_key, idx in state_map.items()}
        }
