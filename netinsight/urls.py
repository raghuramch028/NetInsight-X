from django.urls import include, path

urlpatterns = [
    path("", include("netinsight.dashboard.urls")),
]
