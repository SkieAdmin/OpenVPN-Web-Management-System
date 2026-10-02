import ipaddress
import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from . import wg


class Server(models.Model):
    CONNECTION_SSH = "ssh"
    CONNECTION_LOCAL = "local"
    CONNECTION_CHOICES = [
        (CONNECTION_LOCAL, "Local (this app runs on the VPN server itself)"),
        (CONNECTION_SSH, "SSH (manage a remote Linux server)"),
    ]

    name = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=255, blank=True)

    # WireGuard
    endpoint_host = models.CharField(
        "Public endpoint", max_length=255,
        help_text="Public IP or hostname clients connect to, e.g. 103.164.54.159",
    )
    listen_port = models.PositiveIntegerField(default=51820)
    interface = models.CharField(max_length=15, default="wg0")
    config_path = models.CharField(
        max_length=255, default="/etc/wireguard/wg0.conf",
        help_text="SSH mode only. Local mode always uses /etc/wireguard/<interface>.conf.",
    )
    public_key = models.CharField(
        "Server public key", max_length=64, blank=True,
        help_text="Filled automatically by 'Import from server'.",
    )
    server_address = models.CharField(
        max_length=128, default="10.7.0.1/24",
        help_text="Server tunnel address(es), e.g. '10.7.0.1/24' or '10.7.0.1/24, fddd:2c4:2c4:2c4::1/64'",
    )
    dns = models.CharField("Client DNS", max_length=128, default="1.1.1.1", blank=True)
    client_allowed_ips = models.CharField(
        "Client AllowedIPs", max_length=255, default="0.0.0.0/0, ::/0",
        help_text="0.0.0.0/0, ::/0 = full tunnel (all traffic through the VPN).",
    )
    persistent_keepalive = models.PositiveIntegerField(default=25)
    mtu = models.PositiveIntegerField("Client MTU", null=True, blank=True)

    # Management connection
    connection = models.CharField(max_length=8, choices=CONNECTION_CHOICES, default=CONNECTION_LOCAL)
    ssh_host = models.CharField("SSH host", max_length=255, blank=True)
    ssh_port = models.PositiveIntegerField("SSH port", default=22)
    ssh_user = models.CharField("SSH user", max_length=64, default="root", blank=True)
    ssh_key_path = models.CharField(
        "SSH private key file", max_length=500, blank=True,
        help_text=r"Recommended. e.g. C:\Users\you\.ssh\id_ed25519",
    )
    ssh_password = models.CharField(
        "SSH password", max_length=255, blank=True,
        help_text="Only if you do not use a key. Stored in the local database.",
    )
    use_sudo = models.BooleanField(
        default=False, help_text="Tick when the SSH user is not root (needs passwordless sudo).",
    )
    client_conf_dir = models.CharField(
        max_length=255, default="/root", blank=True,
        help_text="SSH mode only: where wireguard-install saved client .conf files (used to recover keys on "
                  "import). Local mode uses CLIENT_DIRS in the helper script.",
    )
    auto_apply = models.BooleanField(
        default=True, help_text="Push peer changes to the server immediately after every edit.",
    )

    last_applied_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=32, blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    # --- addressing ---
    def addresses(self):
        return wg.split_addresses(self.server_address)

    @property
    def ipv4_network(self):
        v4, _ = self.addresses()
        return v4.network if v4 else None

    @property
    def ipv6_network(self):
        _, v6 = self.addresses()
        return v6.network if v6 else None

    @property
    def endpoint(self):
        host = self.endpoint_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"  # bare IPv6
        return f"{host}:{self.listen_port}"

    def clean(self):
        v4, _ = self.addresses()
        if v4 is None:
            raise ValidationError({"server_address": "Needs at least one IPv4 address like 10.7.0.1/24."})
        if self.public_key and not wg.is_valid_key(self.public_key):
            raise ValidationError({"public_key": "Not a valid WireGuard key."})
        if self.connection == self.CONNECTION_SSH and not self.ssh_host:
            raise ValidationError({"ssh_host": "Required for SSH connection."})
        if not re.match(r"^[A-Za-z0-9_=+.-]{1,15}$", self.interface or ""):
            raise ValidationError({"interface": "Invalid interface name, e.g. wg0."})

    def next_free_ipv4(self):
        v4, _ = self.addresses()
        used = {str(v4.ip)}
        used.update(self.clients.values_list("ipv4", flat=True))
        for host in v4.network.hosts():
            if str(host) not in used:
                return str(host)
        return None

    def ipv6_for(self, ipv4: str):
        """Mirror the IPv4 host number into the IPv6 subnet (wireguard-install style)."""
        v4, v6 = self.addresses()
        if not v6 or not ipv4:
            return None
        offset = int(ipaddress.ip_address(ipv4)) - int(v4.network.network_address)
        return str(v6.network.network_address + offset)

    def status_label(self):
        return self.last_status or "unknown"


class Client(models.Model):
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="clients")
    name = models.CharField(max_length=64)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="vpn_clients", help_text="Account allowed to see and download this config.",
    )
    enabled = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Optional. Disabled automatically after this.")
    notes = models.TextField(blank=True)

    ipv4 = models.GenericIPAddressField(protocol="IPv4")
    ipv6 = models.GenericIPAddressField(protocol="IPv6", null=True, blank=True)
    private_key = models.CharField(max_length=64, blank=True)
    public_key = models.CharField(max_length=64)
    preshared_key = models.CharField(max_length=64, blank=True)
    imported = models.BooleanField(default=False)

    # Cached from `wg show dump`
    last_handshake = models.DateTimeField(null=True, blank=True)
    last_endpoint = models.CharField(max_length=128, blank=True)
    rx_bytes = models.BigIntegerField(default=0)
    tx_bytes = models.BigIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["server__name", "name"]
        constraints = [
            models.UniqueConstraint(fields=["server", "name"], name="unique_client_name_per_server"),
            models.UniqueConstraint(fields=["server", "ipv4"], name="unique_client_ip_per_server"),
            models.UniqueConstraint(fields=["server", "public_key"], name="unique_client_key_per_server"),
        ]

    def __str__(self):
        return f"{self.name} ({self.server})"

    @property
    def is_expired(self):
        return bool(self.expires_at and self.expires_at <= timezone.now())

    @property
    def is_active(self):
        return self.enabled and not self.is_expired

    @property
    def is_online(self):
        return bool(self.last_handshake and (timezone.now() - self.last_handshake).total_seconds() < 180)

    @property
    def can_download(self):
        return bool(self.private_key and self.server.public_key)

    def server_allowed_ips(self):
        ips = [f"{self.ipv4}/32"]
        if self.ipv6:
            ips.append(f"{self.ipv6}/128")
        return ", ".join(ips)

    def client_addresses(self):
        v4, v6 = self.server.addresses()
        parts = [f"{self.ipv4}/{v4.network.prefixlen}"]
        if self.ipv6 and v6:
            parts.append(f"{self.ipv6}/{v6.network.prefixlen}")
        return ", ".join(parts)

    def render_config(self):
        s = self.server
        return wg.render_client_config(
            private_key=self.private_key,
            addresses=self.client_addresses(),
            dns=s.dns,
            mtu=s.mtu,
            server_public_key=s.public_key,
            preshared_key=self.preshared_key,
            allowed_ips=s.client_allowed_ips,
            endpoint=s.endpoint,
            keepalive=s.persistent_keepalive,
        )

    def config_filename(self):
        # WireGuard for Windows uses the file name as the tunnel name (max 32 chars).
        return f"{wg.safe_peer_name(self.server.name)}-{wg.safe_peer_name(self.name)}"[:32] + ".conf"

    def regenerate_keys(self):
        self.private_key, self.public_key = wg.generate_keypair()
        self.preshared_key = wg.generate_preshared_key()
        self.imported = False


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=64)
    target = models.CharField(max_length=255, blank=True)
    detail = models.TextField(blank=True)
    success = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.action} {self.target}"

    @classmethod
    def record(cls, user, action, target="", detail="", success=True):
        return cls.objects.create(
            user=user if getattr(user, "is_authenticated", False) else None,
            action=action, target=str(target)[:255], detail=detail, success=success,
        )
