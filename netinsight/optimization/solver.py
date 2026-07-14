import logging

import cvxopt
import numpy as np

from netinsight.config import settings
from netinsight.optimization.kkt import KKTVerifier

logger = logging.getLogger(__name__)

# Suppress CVXOPT console print messages
cvxopt.solvers.options['show_progress'] = False

class BandwidthOptimizer:
    """Solves bandwidth allocation constraints using Linear Programming and CVXOPT.

    Validates results numerically using KKT verification.
    """

    def __init__(self):
        self.kkt_verifier = KKTVerifier()

    def solve_allocation(self, priorities: list[float] = None, min_bounds: list[float] = None, max_bounds: list[float] = None, total_capacity: float = None) -> dict:
        """Solves the Linear Programming allocation problem.

        Maximize  sum(c_i * x_i)
        Subject to:
                  sum(x_i) <= B
                  x_i >= m_i  (min_bounds)
                  x_i <= M_i  (max_bounds)

        Args:
            priorities: Weight priorities for each class (c).
            min_bounds: Minimum QoS limits (m).
            max_bounds: Maximum limits (M).
            total_capacity: Total link capacity (B).

        Returns:
            dict: Solver outcomes containing state, allocations, objective utility, and KKT verification status.
        """
        # Load from config settings if parameters are omitted
        c_priorities = priorities if priorities is not None else settings.QOS_PRIORITIES
        m_min = min_bounds if min_bounds is not None else settings.QOS_MIN_BANDWIDTH
        M_max = max_bounds if max_bounds is not None else settings.QOS_MAX_BANDWIDTH
        B_capacity = total_capacity if total_capacity is not None else settings.LINK_CAPACITY

        n_classes = len(c_priorities)

        # Verify dimension matches
        if len(m_min) != n_classes or len(M_max) != n_classes:
            error_msg = "Dimension mismatch between priorities and bounds lists."
            logger.error(error_msg)
            return self._fallback_allocation(c_priorities, m_min, M_max, B_capacity, "failure")

        # Check basic feasibility: if sum of minimum QoS requirements exceeds capacity, it's infeasible
        if sum(m_min) > B_capacity:
            logger.warning(
                f"Optimization problem is structurally infeasible. "
                f"Sum of QoS minimums ({sum(m_min)/1e6:.2f} Mbps) exceeds link capacity ({B_capacity/1e6:.2f} Mbps)."
            )
            return self._fallback_allocation(c_priorities, m_min, M_max, B_capacity, "infeasible")

        # Determine scale factor dynamically to avoid numerical instability
        # If capacity represents real network bandwidth (e.g., > 10 Kbps), scale by 1e6 to solve in Mbps
        scale = 1e6 if B_capacity > 10000.0 else 1.0

        # Scale parameters
        m_min_scaled = [float(m) / scale for m in m_min]
        M_max_scaled = [float(M) / scale for M in M_max]
        B_capacity_scaled = float(B_capacity) / scale

        # Formulate matrices for CVXOPT LP (scaled problem)
        # Minimize -c^T * x to maximize c^T * x
        c_mat = cvxopt.matrix([-float(p) for p in c_priorities])

        G_list = []
        h_list = []

        # Sum constraint (sum(x_i) <= B_scaled)
        G_list.append([1.0] * n_classes)
        h_list.append(float(B_capacity_scaled))

        # Lower bounds (-x_i <= -m_scaled)
        for i in range(n_classes):
            row = [0.0] * n_classes
            row[i] = -1.0
            G_list.append(row)
            h_list.append(-float(m_min_scaled[i]))

        # Upper bounds (x_i <= M_scaled)
        for i in range(n_classes):
            row = [0.0] * n_classes
            row[i] = 1.0
            G_list.append(row)
            h_list.append(float(M_max_scaled[i]))

        G_mat = cvxopt.matrix(G_list).T
        h_mat = cvxopt.matrix(h_list)

        try:
            # Solve using CVXOPT on scaled problem
            solution = cvxopt.solvers.lp(c_mat, G_mat, h_mat)
            status = solution['status']

            if status == 'optimal':
                x_opt = list(solution['x'])
                z_opt = list(solution['z'])

                # Convert scaled values to arrays for KKT verification
                x_arr = np.array(x_opt).flatten()
                z_arr = np.array(z_opt).flatten()
                c_arr = np.array([-float(p) for p in c_priorities])
                G_arr = np.array(G_list)
                h_arr = np.array(h_list)

                # Verify KKT conditions on the scaled problem
                kkt_results = self.kkt_verifier.verify(c_arr, G_arr, h_arr, x_arr, z_arr)

                # Scale primal allocations back to original bps
                allocations_bps = [float(x) * scale for x in x_opt]
                utility = float(sum(p * x for p, x in zip(c_priorities, allocations_bps, strict=False)))

                return {
                    "status": "optimal",
                    "allocations": allocations_bps,
                    "utility": utility,
                    "kkt_results": kkt_results
                }
            else:
                logger.error(f"CVXOPT solver returned non-optimal status: {status}")
                return self._fallback_allocation(c_priorities, m_min, M_max, B_capacity, status)

        except Exception as e:
            logger.error(f"Exception raised in CVXOPT LP solver: {e}", exc_info=True)
            return self._fallback_allocation(c_priorities, m_min, M_max, B_capacity, "failure")

    def _fallback_allocation(self, priorities: list[float], min_bounds: list[float], max_bounds: list[float], total_capacity: float, status: str) -> dict:
        """Computes a proportional fallback allocation when solver fails or is infeasible.

        Allocation Heuristic:
            If total capacity is enough for minimum QoS requirements:
                Allocate minimum bounds first.
                Distribute remaining capacity proportionally based on priorities and upper bounds.
            Else (extremely congested):
                Scale down minimum bounds proportionally so that the sum matches total capacity.
        """
        logger.info(f"Computing proportional fallback allocation (Status: {status})...")
        n_classes = len(priorities)
        allocations = [0.0] * n_classes
        sum_min = sum(min_bounds)

        if sum_min <= total_capacity:
            # Phase 1: Allocate minimums
            allocations = [float(m) for m in min_bounds]
            remaining = total_capacity - sum_min

            # Phase 2: Allocate remaining proportionally to weights, respecting max limits
            total_priority = sum(priorities)
            if total_priority > 0 and remaining > 0:
                for i in range(n_classes):
                    weight_ratio = priorities[i] / total_priority
                    added = weight_ratio * remaining
                    max_addition = max_bounds[i] - allocations[i]
                    allocations[i] += min(added, max_addition)
        else:
            # Scale down minimum requirements proportionally to fit total capacity
            scale = total_capacity / sum_min
            allocations = [float(m * scale) for m in min_bounds]

        utility = float(sum(p * x for p, x in zip(priorities, allocations, strict=False)))

        # Build mock empty KKT report since solver failed
        kkt_dummy = {
            "is_optimal": False,
            "primal_feasible": False,
            "max_primal_violation": 0.0,
            "dual_feasible": False,
            "min_dual_multiplier": 0.0,
            "complementary_slackness_satisfied": False,
            "max_complementary_slackness_violation": 0.0,
            "stationarity_satisfied": False,
            "max_stationarity_violation": 0.0,
            "residuals": {"primal": [], "comp_slack": [], "stationarity": []}
        }

        return {
            "status": f"fallback ({status})",
            "allocations": allocations,
            "utility": utility,
            "kkt_results": kkt_dummy
        }
