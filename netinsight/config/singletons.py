"""Centralized thread-safe singleton registry for NetInsight-X business engine components."""

import threading

_analytics_engine = None
_dse_engine = None
_hmm_predictor = None
_traffic_classifier = None
_lp_optimizer = None
_mdp_engine = None

_lock = threading.Lock()

def get_analytics_engine():
    """Returns the process-wide shared AnalyticsEngine singleton."""
    global _analytics_engine
    if _analytics_engine is None:
        with _lock:
            if _analytics_engine is None:
                from netinsight.analytics.engine import AnalyticsEngine
                _analytics_engine = AnalyticsEngine()
    return _analytics_engine

def get_dse_engine():
    """Returns the process-wide shared DecisionSupportEngine singleton."""
    global _dse_engine
    if _dse_engine is None:
        with _lock:
            if _dse_engine is None:
                from netinsight.prediction.dse import DecisionSupportEngine
                _dse_engine = DecisionSupportEngine()
    return _dse_engine

def get_hmm_predictor():
    """Returns the process-wide shared HiddenMarkovModel singleton."""
    global _hmm_predictor
    if _hmm_predictor is None:
        with _lock:
            if _hmm_predictor is None:
                from netinsight.prediction.hmm import HiddenMarkovModel
                _hmm_predictor = HiddenMarkovModel()
    return _hmm_predictor

def get_traffic_classifier():
    """Returns the process-wide shared TrafficClassifier singleton."""
    global _traffic_classifier
    if _traffic_classifier is None:
        with _lock:
            if _traffic_classifier is None:
                from netinsight.classification.classifier import TrafficClassifier
                _traffic_classifier = TrafficClassifier()
    return _traffic_classifier

def get_lp_optimizer():
    """Returns the process-wide shared BandwidthOptimizer singleton."""
    global _lp_optimizer
    if _lp_optimizer is None:
        with _lock:
            if _lp_optimizer is None:
                from netinsight.optimization.solver import BandwidthOptimizer
                _lp_optimizer = BandwidthOptimizer()
    return _lp_optimizer

def get_mdp_engine():
    """Returns the process-wide shared MDPRecommendationEngine singleton."""
    global _mdp_engine
    if _mdp_engine is None:
        with _lock:
            if _mdp_engine is None:
                from netinsight.prediction.mdp import MDPRecommendationEngine
                _mdp_engine = MDPRecommendationEngine()
    return _mdp_engine
