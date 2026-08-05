import os
import shutil
import tempfile
import unittest
from pathlib import Path

from django.test import TestCase

from netinsight.config import settings
from netinsight.database import db_manager
from netinsight.prediction.markov import MarkovPredictor
from netinsight.prediction.mdp import MDPRecommendationEngine
from netinsight.prediction.hmm import HiddenMarkovModel


class TestPredictionModule(TestCase):

    @classmethod
    def setUpClass(cls):
        cls._orig_db_path = settings.DB_PATH
        cls.test_db_dir = tempfile.mkdtemp()
        settings.DB_PATH = str(Path(cls.test_db_dir) / "test_netinsight_prediction.db")
        os.environ["NETINSIGHT_DB_PATH"] = settings.DB_PATH

    @classmethod
    def tearDownClass(cls):
        settings.DB_PATH = cls._orig_db_path
        shutil.rmtree(cls.test_db_dir, ignore_errors=True)

    def setUp(self):
        db_manager.init_db()
        db_manager.clear_db()
        self.predictor = MarkovPredictor()
        self.mdp_engine = MDPRecommendationEngine()

    def tearDown(self):
        db_manager.clear_db()

    def test_deterministic_state_classifier(self):
        """Tests that utilization and loss metrics map to correct network states."""
        # Normal threshold: util < 40%, loss < 2%
        self.assertEqual(self.predictor.classify_state(0.25, 0.01), "Normal")
        # Busy threshold: 40% <= util < 75%, loss < 5%
        self.assertEqual(self.predictor.classify_state(0.50, 0.03), "Busy")
        # Congested threshold: 75% <= util < 95%, loss < 10%
        self.assertEqual(self.predictor.classify_state(0.80, 0.07), "Congested")
        # Under Attack threshold: util >= 95% or loss >= 10%
        self.assertEqual(self.predictor.classify_state(0.96, 0.02), "Under Attack")
        self.assertEqual(self.predictor.classify_state(0.50, 0.12), "Under Attack")

    def test_markov_matrix_estimation(self):
        """Tests estimation of transition matrix from state history.

        Mock sequence of 7 states:
        Normal -> Busy -> Normal -> Busy -> Congested -> Under Attack -> Congested

        Transitions count:
        - Normal to Busy: 2
        - Busy to Normal: 1
        - Busy to Congested: 1
        - Congested to Under Attack: 1
        - Under Attack to Congested: 1

        Total transitions:
        - Out of Normal: 2 (both to Busy). Probabilities: Normal -> Busy = 1.0, others = 0.0
        - Out of Busy: 2 (1 to Normal, 1 to Congested). Probabilities: Busy -> Normal = 0.5, Busy -> Congested = 0.5
        - Out of Congested: 1 (to Under Attack). Probabilities: Congested -> Under Attack = 1.0
        - Out of Under Attack: 1 (to Congested). Probabilities: Under Attack -> Congested = 1.0
        """
        history_seq = ["Normal", "Busy", "Normal", "Busy", "Congested", "Under Attack", "Congested"]

        # Save sequence into state_history table
        timestamp = 10000.0
        for state in history_seq:
            db_manager.save_state_history(timestamp, state, 0.0, 0.0, 0.015)
            timestamp += 10.0 # 10s intervals

        P = self.predictor.estimate_transition_matrix()

        # Row 0: Normal transitions
        self.assertAlmostEqual(P[0, 1], 1.0, places=4) # Normal -> Busy
        self.assertAlmostEqual(P[0, 0], 0.0, places=4)

        # Row 1: Busy transitions
        self.assertAlmostEqual(P[1, 0], 0.5, places=4) # Busy -> Normal
        self.assertAlmostEqual(P[1, 2], 0.5, places=4) # Busy -> Congested
        self.assertAlmostEqual(P[1, 1], 0.0, places=4)

        # Row 2: Congested transitions
        self.assertAlmostEqual(P[2, 3], 1.0, places=4) # Congested -> Under Attack

        # Row 3: Under Attack transitions
        self.assertAlmostEqual(P[3, 2], 1.0, places=4) # Under Attack -> Congested

        # Test future prediction (k=1) from Busy
        pred_dict = self.predictor.predict_state_distribution("Busy", k_steps=1)
        self.assertAlmostEqual(pred_dict["prediction"]["Normal"], 0.5, places=4)
        self.assertAlmostEqual(pred_dict["prediction"]["Congested"], 0.5, places=4)
        self.assertAlmostEqual(pred_dict["prediction"]["Busy"], 0.0, places=4)

    def test_mdp_value_iteration_convergence(self):
        """Verifies that the MDP Value Iteration algorithm converges and generates a policy."""
        V, policy = self.mdp_engine.solve_value_iteration()

        self.assertEqual(len(V), 5)
        self.assertEqual(len(policy), 5)

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

    def test_hmm_viterbi_decoding(self):
        """Tests HiddenMarkovModel.decode_states against a known sequence of observation vectors."""
        hmm = HiddenMarkovModel()

        # Sequence of observations matching Normal -> Busy -> Congested
        obs_seq = [
            {"util": 15.0, "latency": 0.012, "loss": 0.1, "packet_rate": 10.0, "sockets": 5.0, "threat_label": "Normal"},
            {"util": 55.0, "latency": 0.045, "loss": 1.2, "packet_rate": 60.0, "sockets": 25.0, "threat_label": "Normal"},
            {"util": 85.0, "latency": 0.150, "loss": 6.5, "packet_rate": 150.0, "sockets": 70.0, "threat_label": "Normal"}
        ]

        decoded_path = hmm.decode_states(obs_seq)

        self.assertEqual(len(decoded_path), 3)
        self.assertEqual(decoded_path[0], "Normal")
        self.assertEqual(decoded_path[1], "Busy")
        self.assertEqual(decoded_path[2], "Congested")

if __name__ == "__main__":
    unittest.main()
