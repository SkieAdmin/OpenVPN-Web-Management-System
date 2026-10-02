"""Run shell commands on the VPN server, over SSH or locally."""
import shlex
import subprocess
from pathlib import Path

import paramiko
from django.conf import settings

KNOWN_HOSTS = Path(settings.BASE_DIR) / "known_hosts"


class RemoteError(Exception):
    pass


class _Base:
    def __init__(self, server):
        self.server = server

    def wrap(self, command: str) -> str:
        # Always go through bash so process substitution like <(...) works.
        cmd = f"bash -c {shlex.quote(command)}"
        if self.server.use_sudo:
            cmd = f"sudo -n {cmd}"
        return cmd

    def run(self, command: str, stdin: str | None = None, check: bool = True):
        code, out, err = self._exec(self.wrap(command), stdin)
        if check and code != 0:
            raise RemoteError(f"`{command}` failed (exit {code}): {(err or out).strip()[:500]}")
        return code, out, err

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        pass


class LocalRunner(_Base):
    def _exec(self, command, stdin):
        try:
            proc = subprocess.run(
                command, shell=True, input=stdin, capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RemoteError(str(exc)) from exc
        return proc.returncode, proc.stdout, proc.stderr


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

    def _exec(self, command, stdin):
        try:
            chan_in, chan_out, chan_err = self.client.exec_command(command, timeout=60)
            if stdin is not None:
                chan_in.write(stdin)
                chan_in.channel.shutdown_write()
            out = chan_out.read().decode(errors="replace")
            err = chan_err.read().decode(errors="replace")
            code = chan_out.channel.recv_exit_status()
        except (paramiko.SSHException, OSError) as exc:
            raise RemoteError(f"SSH command failed: {exc}") from exc
        return code, out, err

    def close(self):
        self.client.close()


def connect(server):
    if server.connection == server.CONNECTION_LOCAL:
        return LocalRunner(server)
    return SSHRunner(server)
