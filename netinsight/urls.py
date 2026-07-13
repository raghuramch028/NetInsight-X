from django.urls import path, include

urlpatterns = [
    path("", include("netinsight.dashboard.urls")),
]
