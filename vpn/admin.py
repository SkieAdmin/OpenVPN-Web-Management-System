from django.contrib import admin

from .models import AuditLog, Client, Server


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ["name", "endpoint_host", "listen_port", "interface", "connection", "last_status"]


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ["name", "server", "ipv4", "owner", "enabled", "expires_at", "last_handshake"]
    list_filter = ["server", "enabled"]
    search_fields = ["name", "ipv4", "public_key"]
    exclude = ["private_key", "preshared_key"]


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ["created_at", "user", "action", "target", "success"]
    list_filter = ["action", "success"]
