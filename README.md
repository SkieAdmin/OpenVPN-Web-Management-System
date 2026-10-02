# PrivateVPN

A small Django web app for managing a WireGuard VPN server: services, VPN users (one per device), login accounts, and config downloads with QR codes.

It runs on your Windows PC and controls the Linux server over SSH. It can also run on the server itself (choose "Local" as the connection type).

## Start

Double-click `start.bat`, then open http://127.0.0.1:8905/

The first login is `admin` / `admin2027`. **Change it right away** (click your username at the top right).

To start it manually:

```
.venv\Scripts\python.exe manage.py migrate
.venv\Scripts\python.exe manage.py bootstrap_admin
.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8905
```

## First-time setup

1. **Services → Add service**
   - Public endpoint: your server IP, e.g. `103.164.54.159`
   - Connection: SSH, host = the same IP, user `root`
   - SSH private key file: e.g. `C:\Users\you\.ssh\id_ed25519` (recommended). A password also works.
   - Keep the other defaults if the server was installed with the `wireguard-install` script.
2. Open the service and click **1. Test connection**.
3. Click **2. Import from server**. This reads the server public key and your existing peers, so nobody gets disconnected. If the matching client `.conf` files are still in `/root`, their private keys are recovered and those configs become downloadable.
4. **VPN Users → Add VPN user**. The app generates the keys and picks the next free IP. With auto-apply on, the server is updated straight away using `wg syncconf`, so current connections are not dropped.
5. Click **Download .conf** (or scan the QR code on a phone) and import it in the WireGuard app.

## Roles

- **Admin accounts** (`is_staff`) manage services, VPN users, accounts and the activity log.
- **Normal accounts** only see the VPN users they own, and can download those configs.

Set the **Owner** on a VPN user to give an account access to it.

## How "Apply" works

1. Reads the server config (`/etc/wireguard/wg0.conf`).
2. Keeps the `[Interface]` part exactly as it is.
3. Replaces all `[Peer]` blocks with the active VPN users from this app. It uses the same `# BEGIN_PEER` format as the `wireguard-install` script, so that script keeps working.
4. Saves a backup at `wg0.conf.privatevpn.bak`.
5. Hot-reloads WireGuard with `wg syncconf`.

Apply refuses to run if the server has peers this app doesn't know about. Run Import first. "Force apply" deletes those unknown peers instead.

Disabled and expired users are left out of the server config. They stay in the database, so you can turn them back on later.

## Security notes

- `db.sqlite3` holds every client private key, plus the SSH password if you saved one. Keep this folder private and back it up.
- Only use the app from `127.0.0.1`. If you expose it on a network, set `PRIVATEVPN_DEBUG=0`, `PRIVATEVPN_ALLOWED_HOSTS`, and use HTTPS with a strong admin password.
- The SSH host key is pinned in `known_hosts` the first time you connect. If the server is reinstalled, delete its line from that file.
- If the SSH user is not root, tick **use sudo**. That user needs passwordless sudo for `wg`, `wg-quick`, `systemctl`, `cat`, `cp`, `mv` and `chmod`.

## Tests

```
.venv\Scripts\python.exe manage.py test vpn
```
