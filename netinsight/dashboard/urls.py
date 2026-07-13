from django.urls import path
from netinsight.dashboard import views

app_name = "dashboard"

urlpatterns = [
    path("", views.index_view, name="index"),
    path("analytics/", views.analytics_view, name="analytics"),
    path("optimization/", views.optimization_view, name="optimization"),
    path("prediction/", views.prediction_view, name="prediction"),
    path("classification/", views.classification_view, name="classification"),
    path("reports/", views.reports_view, name="reports"),
    path("api/live-metrics/", views.api_live_metrics, name="api_live_metrics"),
    path("api/live-packets/", views.api_live_packets, name="api_live_packets"),
]
