import os
import unittest
import tempfile
import numpy as np
from pathlib import Path

# Setup temporary database path
test_db_dir = tempfile.TemporaryDirectory()
os.environ["NETINSIGHT_DB_PATH"] = str(Path(test_db_dir.name) / "test_netinsight_prediction.db")

from netinsight.database import db_manager
from netinsight.prediction.markov import MarkovPredictor
from netinsight.prediction.mdp import MDPRecommendationEngine

class TestPredictionModule(unittest.TestCase):
    
    def setUp(self):
        db_manager.init_db()
        db_manager.clear_db()
        self.predictor = MarkovPredictor()
        self.mdp_engine = MDPRecommendationEngine()

    def tearDown(self):
        db_manager.clear_db()

    def test_deterministic_state_classifier(self):
        """Tests that utilization and loss metrics map to correct network states."""
        # NORMAL threshold: util < 40%, loss < 2%
        self.assertEqual(self.predictor.classify_state(0.25, 0.01), "NORMAL")
        # BUSY threshold: 40% <= util < 75%, loss < 5%
        self.assertEqual(self.predictor.classify_state(0.50, 0.03), "BUSY")
        # CONGESTED threshold: 75% <= util < 95%, loss < 10%
        self.assertEqual(self.predictor.classify_state(0.80, 0.07), "CONGESTED")
        # FAILURE threshold: util >= 95% or loss >= 10%
        self.assertEqual(self.predictor.classify_state(0.96, 0.02), "FAILURE")
        self.assertEqual(self.predictor.classify_state(0.50, 0.12), "FAILURE")

    def test_markov_matrix_estimation(self):
        """Tests estimation of transition matrix from state history.
        
        Mock sequence of 7 states:
        NORMAL -> BUSY -> NORMAL -> BUSY -> CONGESTED -> FAILURE -> CONGESTED
        
        Transitions count:
        - NORMAL to BUSY: 2
        - BUSY to NORMAL: 1
        - BUSY to CONGESTED: 1
        - CONGESTED to FAILURE: 1
        - FAILURE to CONGESTED: 1
        
        Total transitions:
        - Out of NORMAL: 2 (both to BUSY). Probabilities: NORMAL -> BUSY = 1.0, others = 0.0
        - Out of BUSY: 2 (1 to NORMAL, 1 to CONGESTED). Probabilities: BUSY -> NORMAL = 0.5, BUSY -> CONGESTED = 0.5
        - Out of CONGESTED: 1 (to FAILURE). Probabilities: CONGESTED -> FAILURE = 1.0
        - Out of FAILURE: 1 (to CONGESTED). Probabilities: FAILURE -> CONGESTED = 1.0
        """
        history_seq = ["NORMAL", "BUSY", "NORMAL", "BUSY", "CONGESTED", "FAILURE", "CONGESTED"]
        
        # Save sequence into state_history table
        timestamp = 10000.0
        for state in history_seq:
            db_manager.save_state_history(timestamp, state, 0.0, 0.0, 0.015)
            timestamp += 10.0 # 10s intervals
            
        P = self.predictor.estimate_transition_matrix()
        
        # Row 0: NORMAL transitions
        self.assertAlmostEqual(P[0, 1], 1.0, places=4) # NORMAL -> BUSY
        self.assertAlmostEqual(P[0, 0], 0.0, places=4)
        
        # Row 1: BUSY transitions
        self.assertAlmostEqual(P[1, 0], 0.5, places=4) # BUSY -> NORMAL
        self.assertAlmostEqual(P[1, 2], 0.5, places=4) # BUSY -> CONGESTED
        self.assertAlmostEqual(P[1, 1], 0.0, places=4)
        
        # Row 2: CONGESTED transitions
        self.assertAlmostEqual(P[2, 3], 1.0, places=4) # CONGESTED -> FAILURE
        
        # Row 3: FAILURE transitions
        self.assertAlmostEqual(P[3, 2], 1.0, places=4) # FAILURE -> CONGESTED
        
        # Test future prediction (k=1) from BUSY
        pred_dict = self.predictor.predict_state_distribution("BUSY", k_steps=1)
        self.assertAlmostEqual(pred_dict["prediction"]["NORMAL"], 0.5, places=4)
        self.assertAlmostEqual(pred_dict["prediction"]["CONGESTED"], 0.5, places=4)
        self.assertAlmostEqual(pred_dict["prediction"]["BUSY"], 0.0, places=4)

    def test_mdp_value_iteration_convergence(self):
        """Verifies that the MDP Value Iteration algorithm converges and generates a policy."""
        V, policy = self.mdp_engine.solve_value_iteration()
        
        self.assertEqual(len(V), 4)
        self.assertEqual(len(policy), 4)
        
        # Test recommendations dictionaries
        rec_normal = self.mdp_engine.get_recommendation("NORMAL")
        rec_failure = self.mdp_engine.get_recommendation("FAILURE")
        
        self.assertEqual(rec_normal["current_state"], "NORMAL")
        self.assertEqual(rec_failure["current_state"], "FAILURE")
        
        self.assertIn(rec_normal["recommended_action"], self.mdp_engine.ACTION_NAMES.values())
        self.assertIn(rec_failure["recommended_action"], self.mdp_engine.ACTION_NAMES.values())
        
        # Value iteration rewards: NORMAL should generally favor Reallocate Bandwidth or similar high value
        # and FAILURE should yield values reflecting state transitions
        self.assertGreater(rec_normal["action_values"][rec_normal["recommended_action"]], -50)
        self.assertGreater(rec_failure["action_values"][rec_failure["recommended_action"]], -50)

if __name__ == "__main__":
    unittest.main()
