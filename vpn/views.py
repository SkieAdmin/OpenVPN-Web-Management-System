from functools import wraps

import qrcode
import qrcode.image.svg
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_POST

from . import services
from .forms import AccountForm, ClientForm, ServerForm
from .models import AuditLog, Client, Server


def staff_required(view):
    @login_required
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_staff:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapper


def _report(request, result, action, target):
    level = messages.success if result.ok else messages.error
    level(request, result.message)
    for line in result.details:
        messages.info(request, line)
    AuditLog.record(request.user, action, target, "\n".join([result.message, *result.details]), result.ok)


def _auto_apply(request, server):
    if server.auto_apply:
        _report(request, services.apply_to_server(server), "server.apply", server)
    else:
        messages.warning(request, f"Changes saved. Auto-apply is off: press 'Apply to server' on {server}.")


def _back(request, fallback, **kwargs):
    nxt = request.POST.get("next", "")
    if nxt and url_has_allowed_host_and_scheme(nxt, {request.get_host()}, request.is_secure()):
        return redirect(nxt)
    return redirect(fallback, **kwargs)


def _visible_clients(user):
    qs = Client.objects.select_related("server", "owner")
    return qs if user.is_staff else qs.filter(owner=user)


# --- dashboard ------------------------------------------------------------

@login_required
def dashboard(request):
    if services.expire_clients():
        messages.info(request, "Some clients expired and were disabled. Apply to push the change.")
    clients = _visible_clients(request.user)
    ctx = {
        "clients": clients[:10],
        "client_total": clients.count(),
        "client_enabled": clients.filter(enabled=True).count(),
        "client_online": sum(1 for c in clients if c.is_online),
    }
    if request.user.is_staff:
        ctx["servers"] = Server.objects.annotate(n_clients=Count("clients"))
        ctx["account_total"] = User.objects.count()
        ctx["logs"] = AuditLog.objects.select_related("user")[:8]
    return render(request, "vpn/dashboard.html", ctx)


# --- servers --------------------------------------------------------------

@staff_required
def server_list(request):
    servers = Server.objects.annotate(
        n_clients=Count("clients"), n_enabled=Count("clients", filter=Q(clients__enabled=True)),
    )
    return render(request, "vpn/server_list.html", {"servers": servers})


@staff_required
def server_form(request, pk=None):
    server = get_object_or_404(Server, pk=pk) if pk else None
    form = ServerForm(request.POST or None, instance=server)
    if request.method == "POST" and form.is_valid():
        server = form.save()
        AuditLog.record(request.user, "server.save", server)
        messages.success(request, f"Server '{server}' saved.")
        if not pk:
            messages.info(request, "Next: 'Test connection', then 'Import from server'.")
        return redirect("server_detail", pk=server.pk)
    return render(request, "vpn/server_form.html", {"form": form, "server": server})


@staff_required
def server_detail(request, pk):
    server = get_object_or_404(Server, pk=pk)
    return render(request, "vpn/server_detail.html", {
        "server": server,
        "clients": server.clients.select_related("owner"),
    })


@staff_required
@require_POST
def server_action(request, pk, action):
    server = get_object_or_404(Server, pk=pk)
    if action == "test":
        result = services.test_connection(server)
    elif action == "import":
        result = services.import_from_server(server)
    elif action == "apply":
        services.expire_clients()
        result = services.apply_to_server(server, force=request.POST.get("force") == "1")
    elif action == "status":
        result = services.refresh_status(server)
    elif action in services.SERVICE_ACTIONS:
        result = services.service_action(server, action)
    else:
        raise PermissionDenied
    _report(request, result, f"server.{action}", server)
    return _back(request, "server_detail", pk=server.pk)


@staff_required
def server_delete(request, pk):
    server = get_object_or_404(Server, pk=pk)
    if request.method == "POST":
        AuditLog.record(request.user, "server.delete", server)
        server.delete()
        messages.success(request, "Server removed from the app. Nothing was changed on the real server.")
        return redirect("server_list")
    return render(request, "vpn/confirm_delete.html", {
        "object": server, "kind": "server",
        "warning": f"Removes '{server}' and its {server.clients.count()} client(s) from this app only. "
                   "The real server keeps running unchanged.",
    })


# --- clients --------------------------------------------------------------

@login_required
def client_list(request):
    clients = _visible_clients(request.user)
    q = request.GET.get("q", "").strip()
    server_id = request.GET.get("server", "")
    state = request.GET.get("state", "")
    if q:
        clients = clients.filter(
            Q(name__icontains=q) | Q(ipv4__icontains=q) | Q(owner__username__icontains=q) | Q(notes__icontains=q)
        )
    if server_id.isdigit():
        clients = clients.filter(server_id=server_id)
    if state == "enabled":
        clients = clients.filter(enabled=True)
    elif state == "disabled":
        clients = clients.filter(enabled=False)
    return render(request, "vpn/client_list.html", {
        "clients": clients, "q": q, "server_id": server_id, "state": state,
        "servers": Server.objects.all() if request.user.is_staff else None,
    })


@staff_required
def client_form(request, pk=None):
    client = get_object_or_404(Client, pk=pk) if pk else None
    initial = {}
    if not client and request.GET.get("server", "").isdigit():
        initial["server"] = request.GET["server"]
    if not client and Server.objects.count() == 1:
        initial["server"] = Server.objects.first().pk
    form = ClientForm(request.POST or None, instance=client, initial=initial)
    if not Server.objects.exists():
        messages.warning(request, "Add a server first.")
        return redirect("server_form")
    if request.method == "POST" and form.is_valid():
        changed = form.changed_data
        client = form.save()
        AuditLog.record(request.user, "client.create" if not pk else "client.update", client,
                        ", ".join(changed))
        messages.success(request, f"Client '{client.name}' saved ({client.ipv4}).")
        if not pk or {"enabled", "expires_at", "ipv4", "name"} & set(changed):
            _auto_apply(request, client.server)
        return redirect("client_detail", pk=client.pk)
    return render(request, "vpn/client_form.html", {"form": form, "client": client})


@login_required
def client_detail(request, pk):
    client = get_object_or_404(_visible_clients(request.user), pk=pk)
    qr_svg = None
    if client.can_download:
        img = qrcode.make(client.render_config(), image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
        qr_svg = mark_safe(img.to_string(encoding="unicode"))
    return render(request, "vpn/client_detail.html", {"client": client, "qr_svg": qr_svg})


@login_required
def client_download(request, pk):
    client = get_object_or_404(_visible_clients(request.user), pk=pk)
    if not client.can_download:
        messages.error(request, "Config not available: missing private key (imported peer) or server public key.")
        return redirect("client_detail", pk=pk)
    AuditLog.record(request.user, "client.download", client)
    response = HttpResponse(client.render_config(), content_type="application/octet-stream")
    response["Content-Disposition"] = f'attachment; filename="{client.config_filename()}"'
    return response


@staff_required
@require_POST
def client_toggle(request, pk):
    client = get_object_or_404(Client, pk=pk)
    client.enabled = not client.enabled
    client.save(update_fields=["enabled", "updated_at"])
    AuditLog.record(request.user, "client.enable" if client.enabled else "client.disable", client)
    messages.success(request, f"'{client.name}' {'enabled' if client.enabled else 'disabled'}.")
    _auto_apply(request, client.server)
    return _back(request, "client_list")


@staff_required
@require_POST
def client_regenerate(request, pk):
    client = get_object_or_404(Client, pk=pk)
    client.regenerate_keys()
    client.save()
    AuditLog.record(request.user, "client.regenerate_keys", client)
    messages.warning(request, f"New keys for '{client.name}'. The old config stops working; re-download it.")
    _auto_apply(request, client.server)
    return redirect("client_detail", pk=pk)


@staff_required
def client_delete(request, pk):
    client = get_object_or_404(Client, pk=pk)
    if request.method == "POST":
        server = client.server
        AuditLog.record(request.user, "client.delete", client)
        client.delete()
        messages.success(request, "Client deleted.")
        _auto_apply(request, server)
        return redirect("client_list")
    return render(request, "vpn/confirm_delete.html", {
        "object": client, "kind": "client",
        "warning": "This device loses VPN access once the change is applied to the server.",
    })


# --- accounts -------------------------------------------------------------

@staff_required
def account_list(request):
    users = User.objects.annotate(n_clients=Count("vpn_clients")).order_by("username")
    return render(request, "vpn/account_list.html", {"users": users})


@staff_required
def account_form(request, pk=None):
    user = get_object_or_404(User, pk=pk) if pk else None
    form = AccountForm(request.POST or None, instance=user)
    if request.method == "POST" and form.is_valid():
        if user == request.user and not (form.cleaned_data["is_staff"] and form.cleaned_data["is_active"]):
            form.add_error(None, "You cannot remove your own admin rights or deactivate yourself.")
        else:
            saved = form.save()
            if saved == request.user and form.cleaned_data.get("password1"):
                update_session_auth_hash(request, saved)
            AuditLog.record(request.user, "account.save", saved.username)
            messages.success(request, f"Account '{saved.username}' saved.")
            return redirect("account_list")
    return render(request, "vpn/account_form.html", {"form": form, "account": user})


@staff_required
def account_delete(request, pk):
    user = get_object_or_404(User, pk=pk)
    if user == request.user:
        messages.error(request, "You cannot delete your own account.")
        return redirect("account_list")
    if request.method == "POST":
        AuditLog.record(request.user, "account.delete", user.username)
        user.delete()
        messages.success(request, "Account deleted. Its VPN clients were kept (now without owner).")
        return redirect("account_list")
    return render(request, "vpn/confirm_delete.html", {
        "object": user, "kind": "account",
        "warning": "VPN clients owned by this account are kept but lose their owner.",
    })


@login_required
def password_change(request):
    form = PasswordChangeForm(request.user, request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        update_session_auth_hash(request, user)
        AuditLog.record(request.user, "account.password", user.username)
        messages.success(request, "Password changed.")
        return redirect("dashboard")
    return render(request, "vpn/password_change.html", {"form": form})


@staff_required
def audit_log(request):
    return render(request, "vpn/audit_log.html", {"logs": AuditLog.objects.select_related("user")[:300]})
