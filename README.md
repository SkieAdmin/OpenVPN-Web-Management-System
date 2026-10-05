# PrivateVPN – WireGuard Web Management

A small Django web app for managing a WireGuard VPN server: services, VPN users (one per device), login accounts, and config downloads with QR codes.

It is installed **on the VPN server itself**. You use it from your desktop or laptop in a browser.

```
Desktop / Laptop ──HTTPS──▶ nginx :8443 ──▶ gunicorn (user "privatevpn") ──sudo──▶ privatevpn-helper ──▶ wg / wg-quick / systemd
```

The web app never runs as root. The only thing it can run as root is `/usr/local/sbin/privatevpn-helper`, a short script that checks every argument. It can only:

- read or write `/etc/wireguard/<iface>.conf`
- reload WireGuard
- start, stop or restart `wg-quick@<iface>`
- read peer stats

## Install on the server

The server needs WireGuard already working (for example, installed with `wireguard-install.sh`). Debian, Ubuntu, and Fedora/RHEL-style systems are supported.

```bash
git clone https://github.com/SkieAdmin/OpenVPN-Web-Management-System.git
cd OpenVPN-Web-Management-System
sudo bash deploy/install.sh
```

By default, the panel can **only be reached through the VPN**:

1. Connect WireGuard on your desktop or laptop.
2. Open `https://10.7.0.1:8443`.
3. Accept the self-signed certificate warning once.

Options:

| Flag | Meaning |
|---|---|
| `--public` | Also reachable from the internet at `https://<server-ip>:8443` |
| `--port 9443` | Use another HTTPS port |
| `--interface wg1` | WireGuard interface (default `wg0`) |
| `--endpoint vpn.example.com` | Public address written into client configs (auto-detected otherwise) |
| `--no-nginx --bind 100.64.0.1:8905` | Skip nginx and TLS; gunicorn listens on that address directly |
| `--nginx` | Switch back to nginx on a later run |

`--no-nginx` is for when the panel is already reached over a private network, such as Tailscale, WireGuard or a LAN — that network provides the encryption nginx would have. Never point `--bind` at a public address: the panel hands out VPN private keys and would send them in clear text.

The installer:

- creates the `privatevpn` user
- copies the app to `/opt/privatevpn`
- sets up a Python virtual environment with gunicorn
- installs the helper and its sudo rule
- writes `/etc/privatevpn.env`
- creates a self-signed TLS certificate (skipped with `--no-nginx`)
- configures nginx and opens the firewall port (with `--no-nginx`, removes the nginx site instead)
- starts the `privatevpn` service
- **registers your existing `wg0` and imports its peers**, so nobody gets disconnected

First login: `admin` / `admin2027`. You are **forced to choose a new password** straight away.

### Update

```bash
cd OpenVPN-Web-Management-System
git pull
sudo bash deploy/install.sh
```

Re-running the installer keeps the database, settings and certificate. It also remembers how the panel is served, so a bare re-run updates the code without putting nginx back or changing the bind address. Pass `--nginx` or `--no-nginx --bind HOST:PORT` only when you want to change that.

### Useful commands

```bash
systemctl status privatevpn
```

```bash
journalctl -u privatevpn -f
```

```bash
sudo nano /etc/privatevpn.env && sudo systemctl restart privatevpn
```

| Path | What |
|---|---|
| `/opt/privatevpn` | App code (owned by root) |
| `/var/lib/privatevpn/db.sqlite3` | Database, including client private keys. **Back it up.** |
| `/etc/privatevpn.env` | Settings (secret key, allowed hosts) |
| `/etc/privatevpn/tls.*` | TLS certificate |
| `/etc/wireguard/wg0.conf.privatevpn.bak` | Server config before the last Apply |

## Using it

- **Services**
  - Shows the WireGuard server: status, start, stop, restart.
  - **Import from server** pulls in peers that were added outside the app.
  - **Apply to server** pushes changes. It reloads live with `wg syncconf`, so nobody is disconnected.
- **VPN Users**
  - Each device gets its own keys and the next free IP.
  - You can enable, disable, set an expiry date, make new keys, or delete.
  - **Download .conf** or scan the QR code on a phone.
- **Accounts**
  - **Admins** manage everything.
  - **Normal accounts** only see the VPN users where they are set as **Owner**, and can download those configs.
- **Activity**
  - Every change, config download, and login (including failed ones).

Peers are written in the same `# BEGIN_PEER name` format as `wireguard-install.sh`, so that script keeps working too.

## Security

- **Login lockout:** after 5 wrong passwords, that username and IP are locked out for 15 minutes. The IP is also blocked after 20 failures across all usernames.
- **VPN-only by default.** Only use `--public` if people must download configs without the VPN, and use strong passwords if you do.
- **Private keys are stored in the database.** Anyone with root on the server can read them anyway.
- **Unsure a key is safe?** Leaked keys: open the VPN user and click **Regenerate keys**.

## Development on Windows

`start.bat` runs a local copy at http://127.0.0.1:8000.

It can manage a remote server over SSH: add a service with Connection = **SSH**.

Run the tests:

```
.venv\Scripts\python.exe manage.py test vpn
```
