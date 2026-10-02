from django.contrib.auth import views as auth_views
from django.urls import include, path

from vpn.auth import ThrottledLoginView

# Django's own /admin is intentionally not exposed: it would be a second,
# unthrottled login page. Everything is managed through the vpn app.
urlpatterns = [
    path("login/", ThrottledLoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("vpn.urls")),
]
