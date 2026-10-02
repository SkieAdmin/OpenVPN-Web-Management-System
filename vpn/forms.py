import ipaddress

from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.models import User

from .models import Client, Server


class ServerForm(forms.ModelForm):
    class Meta:
        model = Server
        fields = [
            "name", "description",
            "endpoint_host", "listen_port", "interface", "config_path", "server_address",
            "public_key", "dns", "client_allowed_ips", "persistent_keepalive", "mtu",
            "connection", "ssh_host", "ssh_port", "ssh_user", "ssh_key_path", "ssh_password",
            "use_sudo", "client_conf_dir", "auto_apply",
        ]
        widgets = {
            "ssh_password": forms.PasswordInput(render_value=False),
            "description": forms.TextInput(),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk and self.instance.ssh_password:
            self.fields["ssh_password"].help_text = "A password is saved. Leave blank to keep it."
        self.fields["clear_ssh_password"] = forms.BooleanField(required=False, label="Remove saved SSH password")

    FIELDSETS = [
        ("General", ["name", "description"]),
        ("WireGuard", ["endpoint_host", "listen_port", "interface", "config_path", "server_address", "public_key"]),
        ("Client config defaults", ["dns", "client_allowed_ips", "persistent_keepalive", "mtu"]),
        ("Management connection", ["connection", "ssh_host", "ssh_port", "ssh_user", "ssh_key_path",
                                   "ssh_password", "clear_ssh_password", "use_sudo", "client_conf_dir", "auto_apply"]),
    ]

    def fieldsets(self):
        return [(title, [self[name] for name in names]) for title, names in self.FIELDSETS]

    def clean_ssh_password(self):
        value = self.cleaned_data.get("ssh_password")
        if not value and self.instance.pk:
            return self.instance.ssh_password
        return value

    def save(self, commit=True):
        obj = super().save(commit=False)
        if self.cleaned_data.get("clear_ssh_password"):
            obj.ssh_password = ""
        if commit:
            obj.save()
        return obj


class ClientForm(forms.ModelForm):
    ipv4 = forms.GenericIPAddressField(
        protocol="IPv4", required=False, label="IPv4 address",
        help_text="Leave blank to pick the next free address.",
    )

    class Meta:
        model = Client
        fields = ["server", "name", "owner", "enabled", "expires_at", "ipv4", "notes"]
        widgets = {
            "expires_at": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
            "notes": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = User.objects.order_by("username")
        self.fields["expires_at"].input_formats = ["%Y-%m-%dT%H:%M"]
        if self.instance.pk:
            self.fields["server"].disabled = True

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        if not name:
            raise forms.ValidationError("Name required.")
        return name

    def clean(self):
        data = super().clean()
        server = data.get("server") or getattr(self.instance, "server", None)
        if not server:
            return data
        ip = data.get("ipv4")
        if ip:
            v4, _ = server.addresses()
            addr = ipaddress.ip_address(ip)
            if addr not in v4.network or addr in (v4.network.network_address, v4.network.broadcast_address):
                self.add_error("ipv4", f"Must be a host inside {v4.network}.")
            elif addr == v4.ip:
                self.add_error("ipv4", "That is the server's own address.")
            elif server.clients.filter(ipv4=ip).exclude(pk=self.instance.pk).exists():
                self.add_error("ipv4", "Address already used by another client.")
        elif not self.instance.pk and not server.next_free_ipv4():
            self.add_error("ipv4", f"No free addresses left in {server.ipv4_network}.")
        name = data.get("name")
        if name and server.clients.filter(name=name).exclude(pk=self.instance.pk).exists():
            self.add_error("name", "A client with this name already exists on that server.")
        return data

    def save(self, commit=True):
        client = super().save(commit=False)
        server = client.server
        if not client.ipv4:
            client.ipv4 = self.initial.get("ipv4") or server.next_free_ipv4()
        client.ipv6 = server.ipv6_for(client.ipv4)
        if not client.public_key:
            client.regenerate_keys()
        if commit:
            client.save()
        return client


class AccountForm(forms.ModelForm):
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput, required=False, strip=False)
    password2 = forms.CharField(label="Confirm password", widget=forms.PasswordInput, required=False, strip=False)

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active", "is_staff"]
        labels = {"is_staff": "Administrator (can manage servers, clients and accounts)"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self.fields["password1"].required = True
            self.fields["password2"].required = True
        else:
            self.fields["password1"].help_text = "Leave blank to keep the current password."

    def clean(self):
        data = super().clean()
        p1, p2 = data.get("password1"), data.get("password2")
        if p1 or p2:
            if p1 != p2:
                self.add_error("password2", "Passwords do not match.")
            else:
                try:
                    password_validation.validate_password(p1, self.instance)
                except forms.ValidationError as exc:
                    self.add_error("password1", exc)
        return data

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.cleaned_data.get("password1"):
            user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
