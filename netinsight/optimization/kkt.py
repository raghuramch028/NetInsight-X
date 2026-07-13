import numpy as np
import logging

logger = logging.getLogger(__name__)

class KKTVerifier:
    """Verifies KKT optimality conditions for a solved Linear Programming problem.
    
    LP standard form:
        minimize    c^T x
        subject to  G x <= h
    """
    
    def __init__(self, tolerance: float = 1e-5):
        self.tolerance = tolerance

    def verify(self, c: np.ndarray, G: np.ndarray, h: np.ndarray, x: np.ndarray, z: np.ndarray) -> dict:
        """Verifies the four KKT conditions numerically.
        
        Args:
            c: Objective cost coefficients vector (shape: N,)
            G: Inequality constraint matrix (shape: M, N)
            h: Inequality bounds vector (shape: M,)
            x: Primal optimal solution (shape: N,)
            z: Dual optimal solution (Lagrange multipliers for G x <= h, shape: M,)
            
        Returns:
            dict: Verification results containing residuals and boolean indicators.
        """
        # Convert all to numpy arrays of float type
        c = np.array(c, dtype=float).flatten()
        G = np.array(G, dtype=float)
        h = np.array(h, dtype=float).flatten()
        x = np.array(x, dtype=float).flatten()
        z = np.array(z, dtype=float).flatten()
        
        # 1. Primal Feasibility: G * x <= h
        # Residual represents the maximum constraint violation (must be <= 0 + tolerance)
        primal_residuals = G @ x - h
        primal_feasible = np.all(primal_residuals <= self.tolerance)
        max_primal_violation = float(np.max(primal_residuals)) if len(primal_residuals) > 0 else 0.0

        # 2. Dual Feasibility: z >= 0
        # Residual represents the minimum dual variable (must be >= 0 - tolerance)
        dual_feasible = np.all(z >= -self.tolerance)
        min_dual_val = float(np.min(z)) if len(z) > 0 else 0.0

        # 3. Complementary Slackness: z_j * (G*x - h)_j = 0 for all j
        comp_slack_residuals = z * primal_residuals
        # Since primal_residuals <= 0 and z >= 0, slackness is satisfied if absolute value is within tolerance
        comp_slack_satisfied = np.all(np.abs(comp_slack_residuals) <= self.tolerance)
        max_comp_slack_violation = float(np.max(np.abs(comp_slack_residuals))) if len(comp_slack_residuals) > 0 else 0.0

        # 4. Stationarity: c + G^T * z = 0
        stationarity_residual = c + G.T @ z
        stationarity_satisfied = np.all(np.abs(stationarity_residual) <= self.tolerance)
        max_stationarity_violation = float(np.max(np.abs(stationarity_residual)))

        # Overall optimality check
        optimal = (primal_feasible and dual_feasible and comp_slack_satisfied and stationarity_satisfied)

        results = {
            "is_optimal": optimal,
            "primal_feasible": primal_feasible,
            "max_primal_violation": max_primal_violation,
            "dual_feasible": dual_feasible,
            "min_dual_multiplier": min_dual_val,
            "complementary_slackness_satisfied": comp_slack_satisfied,
            "max_complementary_slackness_violation": max_comp_slack_violation,
            "stationarity_satisfied": stationarity_satisfied,
            "max_stationarity_violation": max_stationarity_violation,
            "residuals": {
                "primal": primal_residuals.tolist(),
                "comp_slack": comp_slack_residuals.tolist(),
                "stationarity": stationarity_residual.tolist()
            }
        }
        
        logger.info(
            f"KKT Verification: Optimal={optimal}, "
            f"PrimalViolation={max_primal_violation:.2e}, "
            f"StationarityViolation={max_stationarity_violation:.2e}"
        )
        return results
