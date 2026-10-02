"""Server operations: import, apply (sync peers), service control, status."""
import ipaddress
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


# --- connection test ------------------------------------------------------

def test_connection(server: Server) -> Result:
    try:
        with connect(server) as r:
            who = r.whoami()
            has_wg, version = r.wg_version()
            readable = r.conf_readable()
            label = r.config_label()
    except RemoteError as exc:
        return Result(False, str(exc))
    details = [f"Commands run as: {who}"]
    details.append(version if has_wg else "WARNING: `wg` not found. Install wireguard-tools.")
    details.append(f"{label} readable" if readable
                   else f"WARNING: cannot read {label} (wrong interface/path or missing root)")
    ok = has_wg and readable
    return Result(ok, "Connection OK" if ok else "Connected with warnings", details)


# --- import ---------------------------------------------------------------

def import_from_server(server: Server) -> Result:
    """Read the server config, fill server settings and create Client rows for unknown peers."""
    try:
        with connect(server) as r:
            conf = wg.parse_server_config(r.read_conf())
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
                if peer.name:
                    text = r.read_client_conf(peer.name)
                    if text:
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
            current = r.read_conf()
            new_text, unknown = build_server_config(server, current)
            if unknown and not force:
                return Result(
                    False,
                    f"Server has {len(unknown)} peer(s) not in this app. Run 'Import from server' first "
                    f"(or 'Force apply' to delete them).",
                    [f"Unknown peer: {k}" for k in unknown],
                )
            live = r.is_active()
            if new_text == current:
                server.last_applied_at = timezone.now()
                server.save(update_fields=["last_applied_at"])
                return Result(True, "Server already up to date.", [f"Service: {live}"])

            r.write_conf(new_text)
            if live == "active":
                r.syncconf()
                note = "Reloaded live (no one was disconnected)."
            else:
                note = f"Config saved. Service is '{live}', start it to use the VPN."
            backup = f"{r.config_label()}.privatevpn.bak"
    except RemoteError as exc:
        return Result(False, str(exc))

    server.last_applied_at = timezone.now()
    server.save(update_fields=["last_applied_at"])
    active = sum(1 for c in server.clients.all() if c.is_active)
    return Result(True, f"Applied {active} active peer(s). {note}", [f"Backup: {backup}"])


# --- service + status -----------------------------------------------------

def service_action(server: Server, action: str) -> Result:
    if action not in SERVICE_ACTIONS:
        return Result(False, f"Unknown action {action}")
    try:
        with connect(server) as r:
            r.service(action)
            if action != "stop":
                try:
                    r.service("enable")
                except RemoteError:
                    pass
            live = r.is_active()
    except RemoteError as exc:
        return Result(False, str(exc))
    server.last_status = live
    server.last_checked_at = timezone.now()
    server.save(update_fields=["last_status", "last_checked_at"])
    return Result(True, f"wg-quick@{server.interface} {action}: now {live}")


def refresh_status(server: Server) -> Result:
    try:
        with connect(server) as r:
            live = r.is_active()
            dump = r.dump() if live == "active" else ""
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
