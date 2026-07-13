import unittest
import numpy as np
from netinsight.optimization.solver import BandwidthOptimizer
from netinsight.optimization.kkt import KKTVerifier

class TestBandwidthOptimization(unittest.TestCase):
    
    def setUp(self):
        self.optimizer = BandwidthOptimizer()
        self.verifier = KKTVerifier()

    def test_toy_lp_problem(self):
        """Tests a known 2-variable LP problem with analytical solution.
        
        Problem:
            Maximize    2*x_1 + 3*x_2
            Subject to  x_1 + x_2 <= 10
                        x_1 >= 1,  x_2 >= 2
                        x_1 <= 6,  x_2 <= 8
                        
        Analytical Solution:
            Since coefficient of x_2 (3) > coefficient of x_1 (2), allocate maximum to x_2 first:
            x_2_opt = 8.0 (upper limit)
            Remaining capacity = 10 - 8 = 2.
            Allocate remaining to x_1:
            x_1_opt = 2.0 (respects lower bound 1.0 and upper bound 6.0)
            Optimal solution: [2.0, 8.0], Utility: 28.0
        """
        priorities = [2.0, 3.0]
        min_bounds = [1.0, 2.0]
        max_bounds = [6.0, 8.0]
        capacity = 10.0
        
        result = self.optimizer.solve_allocation(
            priorities=priorities,
            min_bounds=min_bounds,
            max_bounds=max_bounds,
            total_capacity=capacity
        )
        
        self.assertEqual(result["status"], "optimal")
        allocations = result["allocations"]
        self.assertAlmostEqual(allocations[0], 2.0, places=4)
        self.assertAlmostEqual(allocations[1], 8.0, places=4)
        self.assertAlmostEqual(result["utility"], 28.0, places=4)
        
        # Verify KKT conditions hold
        kkt = result["kkt_results"]
        self.assertTrue(kkt["is_optimal"])
        self.assertTrue(kkt["primal_feasible"])
        self.assertTrue(kkt["dual_feasible"])
        self.assertTrue(kkt["complementary_slackness_satisfied"])
        self.assertTrue(kkt["stationarity_satisfied"])

    def test_realistic_bandwidth_allocation(self):
        """Tests standard 4-class network bandwidth allocation scenario under QoS limits."""
        priorities = [1.0, 2.0, 0.5, 3.0]  # Web, Streaming, File, Critical
        min_bounds = [5e6, 15e6, 2e6, 10e6]  # in bps
        max_bounds = [40e6, 60e6, 30e6, 50e6] # in bps
        capacity = 100e6  # 100 Mbps
        
        result = self.optimizer.solve_allocation(
            priorities=priorities,
            min_bounds=min_bounds,
            max_bounds=max_bounds,
            total_capacity=capacity
        )
        
        self.assertEqual(result["status"], "optimal")
        alloc = result["allocations"]
        
        # Verifies constraints: sum <= capacity
        self.assertLessEqual(sum(alloc), capacity + 1.0)
        
        # Verifies bounds
        for i in range(len(alloc)):
            self.assertGreaterEqual(alloc[i], min_bounds[i] - 1.0)
            self.assertLessEqual(alloc[i], max_bounds[i] + 1.0)
            
        self.assertTrue(result["kkt_results"]["is_optimal"])

    def test_infeasible_fallback_allocation(self):
        """Tests that solver handles infeasibility gracefully by falling back to proportional ratios."""
        priorities = [1.0, 2.0]
        min_bounds = [8e6, 5e6] # Sum = 13e6
        max_bounds = [15e6, 10e6]
        capacity = 10e6  # Infeasible! Sum of mins (13 Mbps) > Capacity (10 Mbps)
        
        result = self.optimizer.solve_allocation(
            priorities=priorities,
            min_bounds=min_bounds,
            max_bounds=max_bounds,
            total_capacity=capacity
        )
        
        # Should execute fallback allocation
        self.assertTrue(result["status"].startswith("fallback"))
        alloc = result["allocations"]
        
        # Sum of allocations must match total capacity exactly
        self.assertAlmostEqual(sum(alloc), capacity, places=2)
        
        # Check that dummy KKT status is optimal=False
        self.assertFalse(result["kkt_results"]["is_optimal"])

if __name__ == "__main__":
    unittest.main()
