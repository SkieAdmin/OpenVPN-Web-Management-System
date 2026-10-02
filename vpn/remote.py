"""Talk to WireGuard on the VPN server.

Two runners expose the same small set of operations:

* LocalRunner - the app runs on the VPN server. Every privileged step goes
  through /usr/local/sbin/privatevpn-helper via sudo, so the web process
  itself never runs as root and can only do what the helper allows.
* SSHRunner   - the app runs elsewhere (e.g. a Windows PC) and manages the
  server over SSH.
"""
import os
import re
import shlex
import subprocess
from pathlib import Path

import paramiko
from django.conf import settings

KNOWN_HOSTS = Path(settings.DATA_DIR) / "known_hosts"
HELPER = settings.PRIVATEVPN_HELPER
IFACE_RE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")
PEER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")


class RemoteError(Exception):
    pass


def _check_iface(server):
    if not IFACE_RE.match(server.interface or ""):
        raise RemoteError(f"Invalid interface name '{server.interface}'.")
    return server.interface


class _Base:
    def __init__(self, server):
        self.server = server
        self.iface = _check_iface(server)
        self.unit = f"wg-quick@{self.iface}"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        pass


class LocalRunner(_Base):
    """Calls the root helper. Runs it directly when already root (e.g. dev box)."""

    def _helper(self, *args, stdin=None, check=True):
        is_root = getattr(os, "geteuid", lambda: -1)() == 0
        cmd = [HELPER, *args] if is_root else ["sudo", "-n", HELPER, *args]
        try:
            proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60)
        except FileNotFoundError as exc:
            raise RemoteError(f"{exc.filename} not found. Run deploy/install.sh on the server.") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RemoteError(str(exc)) from exc
        if check and proc.returncode != 0:
            msg = (proc.stderr or proc.stdout).strip()[:500]
            if "a password is required" in msg or "not allowed" in msg:
                msg += " (sudo rule missing: re-run deploy/install.sh)"
            raise RemoteError(f"helper {args[0]} failed (exit {proc.returncode}): {msg}")
        return proc.returncode, proc.stdout

    def whoami(self):
        return self._helper("whoami")[1].strip()

    def wg_version(self):
        code, out = self._helper("version", check=False)
        return code == 0, out.strip()

    def conf_readable(self):
        return self._helper("read-conf", self.iface, check=False)[0] == 0

    def config_label(self):
        return f"/etc/wireguard/{self.iface}.conf"

    def read_conf(self):
        return self._helper("read-conf", self.iface)[1]

    def write_conf(self, text):
        self._helper("write-conf", self.iface, stdin=text)

    def read_client_conf(self, name):
        if not PEER_NAME_RE.match(name):
            return None
        code, out = self._helper("read-client", name, check=False)
        return out if code == 0 else None

    def is_active(self):
        return self._helper("service", "is-active", self.iface, check=False)[1].strip() or "unknown"

    def service(self, action):
        self._helper("service", action, self.iface)

    def syncconf(self):
        self._helper("syncconf", self.iface)

    def dump(self):
        return self._helper("dump", self.iface, check=False)[1]


class SSHRunner(_Base):
    def __init__(self, server):
        super().__init__(server)
        self.client = paramiko.SSHClient()
        if KNOWN_HOSTS.exists():
            self.client.load_host_keys(str(KNOWN_HOSTS))
        # Trust on first use, then pin the host key in ./known_hosts.
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {
            "hostname": server.ssh_host,
            "port": server.ssh_port,
            "username": server.ssh_user or "root",
            "timeout": 15,
            "banner_timeout": 15,
            "auth_timeout": 15,
        }
        if server.ssh_key_path:
            kwargs["key_filename"] = server.ssh_key_path
            kwargs["look_for_keys"] = False
            kwargs["allow_agent"] = False
        if server.ssh_password:
            kwargs["password"] = server.ssh_password
        try:
            self.client.connect(**kwargs)
        except paramiko.BadHostKeyException as exc:
            raise RemoteError(
                f"SSH host key for {server.ssh_host} CHANGED. Possible man-in-the-middle. "
                f"If you reinstalled the server, remove its line from {KNOWN_HOSTS}."
            ) from exc
        except (paramiko.SSHException, OSError) as exc:
            raise RemoteError(f"SSH connection to {server.ssh_host}:{server.ssh_port} failed: {exc}") from exc
        self.client.save_host_keys(str(KNOWN_HOSTS))
        self.path = shlex.quote(server.config_path)

    def run(self, command, stdin=None, check=True):
        # Always go through bash so process substitution like <(...) works.
        wrapped = f"bash -c {shlex.quote(command)}"
        if self.server.use_sudo:
            wrapped = f"sudo -n {wrapped}"
        try:
            chan_in, chan_out, chan_err = self.client.exec_command(wrapped, timeout=60)
            if stdin is not None:
                chan_in.write(stdin)
                chan_in.channel.shutdown_write()
            out = chan_out.read().decode(errors="replace")
            err = chan_err.read().decode(errors="replace")
            code = chan_out.channel.recv_exit_status()
        except (paramiko.SSHException, OSError) as exc:
            raise RemoteError(f"SSH command failed: {exc}") from exc
        if check and code != 0:
            raise RemoteError(f"`{command}` failed (exit {code}): {(err or out).strip()[:500]}")
        return code, out

    def whoami(self):
        return self.run("id -un")[1].strip()

    def wg_version(self):
        code, out = self.run("wg --version", check=False)
        return code == 0, out.strip()

    def conf_readable(self):
        return self.run(f"test -r {self.path}", check=False)[0] == 0

    def config_label(self):
        return self.server.config_path

    def read_conf(self):
        return self.run(f"cat {self.path}")[1]

    def write_conf(self, text):
        p = self.path
        self.run(f"cp -p {p} {p}.privatevpn.bak")
        self.run(f"umask 077 && cat > {p}.privatevpn.new && mv {p}.privatevpn.new {p} && chmod 600 {p}", stdin=text)

    def read_client_conf(self, name):
        if not PEER_NAME_RE.match(name) or not self.server.client_conf_dir:
            return None
        path = f"{self.server.client_conf_dir.rstrip('/')}/{name}.conf"
        code, out = self.run(f"cat {shlex.quote(path)}", check=False)
        return out if code == 0 else None

    def is_active(self):
        return self.run(f"systemctl is-active {self.unit}", check=False)[1].strip() or "unknown"

    def service(self, action):
        self.run(f"systemctl {action} {self.unit}")

    def syncconf(self):
        self.run(f"wg syncconf {self.iface} <(wg-quick strip {self.iface})")

    def dump(self):
        return self.run(f"wg show {self.iface} dump", check=False)[1]

    def close(self):
        self.client.close()


def connect(server):
    if server.connection == server.CONNECTION_LOCAL:
        return LocalRunner(server)
    return SSHRunner(server)
