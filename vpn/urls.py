from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),

    path("servers/", views.server_list, name="server_list"),
    path("servers/new/", views.server_form, name="server_form"),
    path("servers/<int:pk>/", views.server_detail, name="server_detail"),
    path("servers/<int:pk>/edit/", views.server_form, name="server_edit"),
    path("servers/<int:pk>/delete/", views.server_delete, name="server_delete"),
    path("servers/<int:pk>/action/<slug:action>/", views.server_action, name="server_action"),

    path("clients/", views.client_list, name="client_list"),
    path("clients/new/", views.client_form, name="client_form"),
    path("clients/<int:pk>/", views.client_detail, name="client_detail"),
    path("clients/<int:pk>/edit/", views.client_form, name="client_edit"),
    path("clients/<int:pk>/delete/", views.client_delete, name="client_delete"),
    path("clients/<int:pk>/toggle/", views.client_toggle, name="client_toggle"),
    path("clients/<int:pk>/regenerate/", views.client_regenerate, name="client_regenerate"),
    path("clients/<int:pk>/download/", views.client_download, name="client_download"),

    path("accounts/", views.account_list, name="account_list"),
    path("accounts/new/", views.account_form, name="account_form"),
    path("accounts/<int:pk>/edit/", views.account_form, name="account_edit"),
    path("accounts/<int:pk>/delete/", views.account_delete, name="account_delete"),
    path("password/", views.password_change, name="password_change"),

    path("logs/", views.audit_log, name="audit_log"),
]
