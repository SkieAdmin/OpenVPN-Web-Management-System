"""Server operations: import, apply (sync peers), service control, status."""
import ipaddress
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone as dt_timezone

from django.db import transaction
from django.utils import timezone

from . import wg
from .models import Client, Server
from .remote import RemoteError, connect

SERVICE_ACTIONS = {"start", "stop", "restart"}


@dataclass
class Result:
    ok: bool
    message: str
    details: list = field(default_factory=list)


def _q(value):
    return shlex.quote(str(value))


def _unit(server):
    return f"wg-quick@{server.interface}"


def _read_conf(runner, server):
    _, out, _ = runner.run(f"cat {_q(server.config_path)}")
    return out


# --- connection test ------------------------------------------------------

def test_connection(server: Server) -> Result:
    try:
        with connect(server) as r:
            _, who, _ = r.run("id -un")
            code, ver, _ = r.run("wg --version", check=False)
            code_conf, _, _ = r.run(f"test -r {_q(server.config_path)}", check=False)
    except RemoteError as exc:
        return Result(False, str(exc))
    details = [f"Logged in, commands run as: {who.strip()}"]
    details.append(ver.strip() if code == 0 else "WARNING: `wg` not found. Install wireguard-tools.")
    details.append(
        f"{server.config_path} readable" if code_conf == 0
        else f"WARNING: cannot read {server.config_path} (wrong path or missing root/sudo)"
    )
    return Result(code == 0 and code_conf == 0, "Connection OK" if code == 0 else "Connected with warnings", details)


# --- import ---------------------------------------------------------------

def import_from_server(server: Server) -> Result:
    """Read the server's wg0.conf, fill server settings and create Client rows for unknown peers."""
    try:
        with connect(server) as r:
            conf = wg.parse_server_config(_read_conf(r, server))
            iface = conf.interface.values

            priv = iface.get("PrivateKey", "")
            if wg.is_valid_key(priv):
                server.public_key = wg.public_key_from_private(priv)
            if iface.get("Address"):
                server.server_address = iface["Address"]
            if iface.get("ListenPort", "").isdigit():
                server.listen_port = int(iface["ListenPort"])
            if conf.endpoint_hint and not server.endpoint_host:
                server.endpoint_host = conf.endpoint_hint
            server.save()

            known = set(server.clients.values_list("public_key", flat=True))
            created, recovered, skipped = [], [], []
            for index, peer in enumerate(conf.peers, start=1):
                pub = peer.values.get("PublicKey", "")
                if not wg.is_valid_key(pub) or pub in known:
                    continue
                v4 = v6 = None
                for part in peer.values.get("AllowedIPs", "").split(","):
                    try:
                        net = ipaddress.ip_network(part.strip(), strict=False)
                    except ValueError:
                        continue
                    if net.version == 4 and v4 is None:
                        v4 = str(net.network_address)
                    elif net.version == 6 and v6 is None:
                        v6 = str(net.network_address)
                if not v4:
                    skipped.append(f"peer {pub[:8]}… has no IPv4 AllowedIPs")
                    continue

                name = peer.name or f"imported-{index}"
                base, n = name, 2
                while server.clients.filter(name=name).exists():
                    name = f"{base}-{n}"
                    n += 1

                private_key = ""
                if peer.name and server.client_conf_dir:
                    path = f"{server.client_conf_dir.rstrip('/')}/{peer.name}.conf"
                    code, text, _ = r.run(f"cat {_q(path)}", check=False)
                    if code == 0:
                        candidate = wg.parse_client_config(text)["interface"].get("PrivateKey", "")
                        if wg.is_valid_key(candidate) and wg.public_key_from_private(candidate) == pub:
                            private_key = candidate
                            recovered.append(name)

                Client.objects.create(
                    server=server, name=name, ipv4=v4, ipv6=v6, public_key=pub,
                    preshared_key=peer.values.get("PresharedKey", ""),
                    private_key=private_key, imported=True,
                )
                known.add(pub)
                created.append(name)
    except RemoteError as exc:
        return Result(False, str(exc))

    details = [f"Server public key: {server.public_key or 'not found'}"]
    details += [f"Imported: {n}" for n in created]
    if recovered:
        details.append(f"Recovered private keys (downloadable): {', '.join(recovered)}")
    missing = [n for n in created if n not in recovered]
    if missing:
        details.append(
            "No private key for: " + ", ".join(missing)
            + ". Those devices keep working, but to download a config use 'Regenerate keys'."
        )
    details += skipped
    return Result(True, f"Imported {len(created)} new peer(s).", details)


# --- apply ----------------------------------------------------------------

def build_server_config(server: Server, current_text: str) -> tuple[str, list]:
    parsed = wg.parse_server_config(current_text)
    clients = list(server.clients.all())
    known = {c.public_key for c in clients}
    unknown = [p.values.get("PublicKey", "") for p in parsed.peers if p.values.get("PublicKey") not in known]
    blocks = [
        wg.render_peer_block(c.name, c.public_key, c.preshared_key, c.server_allowed_ips())
        for c in clients if c.is_active
    ]
    return wg.render_server_config(parsed.head, blocks), unknown


def apply_to_server(server: Server, force: bool = False) -> Result:
    """Rewrite the [Peer] part of the server config from the database and hot-reload WireGuard."""
    try:
        with connect(server) as r:
            current = _read_conf(r, server)
            new_text, unknown = build_server_config(server, current)
            if unknown and not force:
                return Result(
                    False,
                    f"Server has {len(unknown)} peer(s) not in this app. Run 'Import from server' first "
                    f"(or 'Force apply' to delete them).",
                    [f"Unknown peer: {k}" for k in unknown],
                )
            if new_text == current:
                live = r.run(f"systemctl is-active {_q(_unit(server))}", check=False)[1].strip()
                server.last_applied_at = timezone.now()
                server.save(update_fields=["last_applied_at"])
                return Result(True, "Server already up to date.", [f"Service: {live}"])

            path = _q(server.config_path)
            r.run(f"cp -p {path} {path}.privatevpn.bak")
            r.run(f"umask 077 && cat > {path}.privatevpn.new && mv {path}.privatevpn.new {path}", stdin=new_text)
            r.run(f"chmod 600 {path}")

            live = r.run(f"systemctl is-active {_q(_unit(server))}", check=False)[1].strip()
            if live == "active":
                iface = _q(server.interface)
                r.run(f"wg syncconf {iface} <(wg-quick strip {iface})")
                note = "Reloaded live (no one was disconnected)."
            else:
                note = f"Config saved. Service is '{live}', start it to use the VPN."
    except RemoteError as exc:
        return Result(False, str(exc))

    server.last_applied_at = timezone.now()
    server.save(update_fields=["last_applied_at"])
    active = sum(1 for c in server.clients.all() if c.is_active)
    return Result(True, f"Applied {active} active peer(s). {note}", [f"Backup: {server.config_path}.privatevpn.bak"])


# --- service + status -----------------------------------------------------

def service_action(server: Server, action: str) -> Result:
    if action not in SERVICE_ACTIONS:
        return Result(False, f"Unknown action {action}")
    try:
        with connect(server) as r:
            r.run(f"systemctl {action} {_q(_unit(server))}")
            if action != "stop":
                r.run(f"systemctl enable {_q(_unit(server))}", check=False)
            live = r.run(f"systemctl is-active {_q(_unit(server))}", check=False)[1].strip()
    except RemoteError as exc:
        return Result(False, str(exc))
    server.last_status = live
    server.last_checked_at = timezone.now()
    server.save(update_fields=["last_status", "last_checked_at"])
    return Result(True, f"{_unit(server)} {action}: now {live}")


def refresh_status(server: Server) -> Result:
    try:
        with connect(server) as r:
            live = r.run(f"systemctl is-active {_q(_unit(server))}", check=False)[1].strip() or "unknown"
            dump = ""
            if live == "active":
                dump = r.run(f"wg show {_q(server.interface)} dump", check=False)[1]
    except RemoteError as exc:
        server.last_status = "unreachable"
        server.last_checked_at = timezone.now()
        server.save(update_fields=["last_status", "last_checked_at"])
        return Result(False, str(exc))

    peers = wg.parse_dump(dump)
    with transaction.atomic():
        for client in server.clients.all():
            info = peers.get(client.public_key)
            if info:
                ts = info["latest_handshake"]
                client.last_handshake = datetime.fromtimestamp(ts, tz=dt_timezone.utc) if ts else None
                client.last_endpoint = info["endpoint"]
                client.rx_bytes = info["rx"]
                client.tx_bytes = info["tx"]
            else:
                client.last_handshake = None
                client.last_endpoint = ""
            client.save(update_fields=["last_handshake", "last_endpoint", "rx_bytes", "tx_bytes"])
        server.last_status = live
        server.last_checked_at = timezone.now()
        server.save(update_fields=["last_status", "last_checked_at"])
    online = sum(1 for c in server.clients.all() if c.is_online)
    return Result(True, f"Service {live}. {online} client(s) online.")


def expire_clients() -> int:
    """Disable clients whose expiry passed. Returns how many changed."""
    return Client.objects.filter(enabled=True, expires_at__lte=timezone.now()).update(enabled=False)
