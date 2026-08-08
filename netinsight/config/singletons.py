"""Centralized thread-safe singleton registry for NetInsight-X business engine components."""

import threading

_analytics_engine = None
_dse_engine = None
_traffic_classifier = None
_lp_optimizer = None

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
                from netinsight.analytics.dse import DecisionSupportEngine
                _dse_engine = DecisionSupportEngine()
    return _dse_engine


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
