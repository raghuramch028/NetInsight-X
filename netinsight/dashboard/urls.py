from django.urls import path
from netinsight.dashboard import views

app_name = "dashboard"

urlpatterns = [
    # Dashboard HTML Pages
    path("", views.index_view, name="index"),
    path("analytics/", views.analytics_view, name="analytics"),
    path("optimization/", views.optimization_view, name="optimization"),
    path("prediction/", views.prediction_view, name="prediction"),
    path("classification/", views.classification_view, name="classification"),
    path("reports/", views.reports_view, name="reports"),
    path("settings/", views.settings_view, name="settings"),

    # REST Telemetry APIs (Versioned)
    path("api/v1/agents/register", views.api_register_agent, name="api_register_agent"),
    path("api/v1/agents/telemetry", views.api_agent_telemetry, name="api_agent_telemetry"),

    # Interactive Topology pyvis API
    path("api/v1/topology/graph", views.api_topology_graph, name="api_topology_graph"),

    # Poll APIs for Chart.js Dashboard Updates
    path("api/live-metrics/", views.api_live_metrics, name="api_live_metrics"),
    path("api/live-packets/", views.api_live_packets, name="api_live_packets"),

    # Reports exports API downloads
    path("reports/pdf/", views.reports_pdf_download, name="reports_pdf_download"),
    path("reports/csv/", views.reports_csv_download, name="reports_csv_download"),
    path("reports/json/", views.reports_json_download, name="reports_json_download"),
]
