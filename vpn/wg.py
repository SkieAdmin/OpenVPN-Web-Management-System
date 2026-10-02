"""Pure WireGuard helpers: key generation and config parsing/rendering.

Nothing in here talks to a server, so it is safe to unit test on Windows.
The server config format matches the Nyr ``wireguard-install`` script
(peers wrapped in ``# BEGIN_PEER name`` / ``# END_PEER name``) so that
script keeps working alongside this app.
"""
import base64
import ipaddress
import os
import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
NAME_RE = re.compile(r"[^A-Za-z0-9_-]")


# --- keys -----------------------------------------------------------------

def generate_private_key() -> str:
    raw = bytearray(os.urandom(32))
    # Clamp exactly like `wg genkey`.
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return base64.b64encode(bytes(raw)).decode()


def public_key_from_private(private_key: str) -> str:
    raw = base64.b64decode(private_key)
    pub = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def generate_preshared_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def generate_keypair() -> tuple[str, str]:
    private = generate_private_key()
    return private, public_key_from_private(private)


def is_valid_key(value: str) -> bool:
    return bool(value) and bool(KEY_RE.match(value.strip()))


def safe_peer_name(name: str) -> str:
    """Peer marker names must be a single token (wireguard-install rule)."""
    cleaned = NAME_RE.sub("_", name.strip())[:15]
    return cleaned or "client"


# --- parsing --------------------------------------------------------------

@dataclass
class Section:
    values: dict = field(default_factory=dict)
    name: str = ""  # from "# BEGIN_PEER <name>" when present


@dataclass
class ServerConfig:
    head: str  # everything before the first peer, kept verbatim
    interface: Section
    peers: list
    endpoint_hint: str = ""  # from "# ENDPOINT x" (wireguard-install)


def _parse_kv(line: str):
    if "=" not in line:
        return None
    key, _, value = line.partition("=")
    return key.strip(), value.strip()


def parse_client_config(text: str) -> dict:
    """Return {'interface': {...}, 'peer': {...}} from a client .conf."""
    result = {"interface": {}, "peer": {}}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low == "[interface]":
            current = result["interface"]
        elif low == "[peer]":
            current = result["peer"]
        elif current is not None:
            kv = _parse_kv(line)
            if kv:
                current[kv[0]] = kv[1]
    return result


def parse_server_config(text: str) -> ServerConfig:
    lines = text.splitlines()
    head_end = len(lines)
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.lower() == "[peer]" or stripped.startswith("# BEGIN_PEER"):
            head_end = i
            break

    head_lines = lines[:head_end]
    interface = Section()
    endpoint_hint = ""
    in_interface = False
    for raw in head_lines:
        line = raw.strip()
        if line.startswith("# ENDPOINT"):
            endpoint_hint = line[len("# ENDPOINT"):].strip()
            continue
        if line.lower() == "[interface]":
            in_interface = True
            continue
        if in_interface and line and not line.startswith("#"):
            kv = _parse_kv(line)
            if kv:
                interface.values[kv[0]] = kv[1]

    peers = []
    pending_name = ""
    current = None
    for raw in lines[head_end:]:
        line = raw.strip()
        if line.startswith("# BEGIN_PEER"):
            pending_name = line[len("# BEGIN_PEER"):].strip()
            continue
        if line.startswith("# END_PEER"):
            current = None
            continue
        if line.lower() == "[peer]":
            current = Section(name=pending_name)
            peers.append(current)
            pending_name = ""
            continue
        if line.startswith("#") or not line:
            continue
        if current is not None:
            kv = _parse_kv(line)
            if kv:
                current.values[kv[0]] = kv[1]

    head = "\n".join(head_lines).rstrip() + "\n"
    return ServerConfig(head=head, interface=interface, peers=peers, endpoint_hint=endpoint_hint)


# --- rendering ------------------------------------------------------------

def render_peer_block(name: str, public_key: str, preshared_key: str, allowed_ips: str) -> str:
    marker = safe_peer_name(name)
    lines = [f"# BEGIN_PEER {marker}", "[Peer]", f"PublicKey = {public_key}"]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append(f"AllowedIPs = {allowed_ips}")
    lines.append(f"# END_PEER {marker}")
    return "\n".join(lines) + "\n"


def render_server_config(head: str, peer_blocks: list) -> str:
    body = head.rstrip() + "\n"
    for block in peer_blocks:
        body += "\n" + block
    return body


def render_client_config(*, private_key, addresses, dns, mtu, server_public_key,
                         preshared_key, allowed_ips, endpoint, keepalive) -> str:
    lines = ["[Interface]", f"PrivateKey = {private_key}", f"Address = {addresses}"]
    if dns:
        lines.append(f"DNS = {dns}")
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines += ["", "[Peer]", f"PublicKey = {server_public_key}"]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append(f"AllowedIPs = {allowed_ips}")
    lines.append(f"Endpoint = {endpoint}")
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


# --- addressing -----------------------------------------------------------

def split_addresses(value: str):
    """'10.7.0.1/24, fddd::1/64' -> (IPv4Interface|None, IPv6Interface|None)."""
    v4 = v6 = None
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            iface = ipaddress.ip_interface(part)
        except ValueError:
            continue
        if iface.version == 4 and v4 is None:
            v4 = iface
        elif iface.version == 6 and v6 is None:
            v6 = iface
    return v4, v6


def parse_dump(text: str) -> dict:
    """Parse `wg show <iface> dump` into {public_key: {...}}."""
    peers = {}
    lines = [l for l in text.splitlines() if l.strip()]
    for line in lines[1:]:  # first line is the interface itself
        cols = line.split("\t")
        if len(cols) < 8:
            continue
        pub, _psk, endpoint, allowed, handshake, rx, tx, _keepalive = cols[:8]
        peers[pub] = {
            "endpoint": "" if endpoint == "(none)" else endpoint,
            "allowed_ips": allowed,
            "latest_handshake": int(handshake or 0),
            "rx": int(rx or 0),
            "tx": int(tx or 0),
        }
    return peers
