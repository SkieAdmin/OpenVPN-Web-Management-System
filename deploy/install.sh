#!/bin/bash
# Install or update the PrivateVPN web panel on the WireGuard server.
#
#   sudo bash deploy/install.sh                       # listen on every address, port 8905
#   sudo bash deploy/install.sh --bind 100.64.0.1:8905  # one address only
#   sudo bash deploy/install.sh --port 9000 --interface wg0 --endpoint vpn.example.com
#
# gunicorn serves the panel directly over plain HTTP. There is no nginx and no
# TLS, because this setup has no domain name to get a certificate for. Reach it
# over a private network (Tailscale, WireGuard, LAN), or restrict it with --bind.
#
# Safe to run again after `git pull` to update. Settings in /etc/privatevpn.env,
# the database and the bind address are kept, so a bare re-run only updates code.
set -euo pipefail

APP_DIR=/opt/privatevpn
DATA_DIR=/var/lib/privatevpn
ENV_FILE=/etc/privatevpn.env
APP_USER=privatevpn
HELPER=/usr/local/sbin/privatevpn-helper
NGINX_CONF=/etc/nginx/conf.d/privatevpn.conf

IFACE=wg0
PORT=""
ENDPOINT=""
BIND=""   # empty = keep what the last run used, else 0.0.0.0:$PORT

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

# Read one setting out of the existing env file, without sourcing it. Prints
# nothing and still succeeds when the file does not exist yet, so a fresh
# install does not trip `set -e`.
env_get() {
	[[ -f "$ENV_FILE" ]] || return 0
	sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

# Add or replace one setting in the env file.
env_set() {
	if grep -q "^$1=" "$ENV_FILE" 2> /dev/null; then
		sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
	else
		echo "$1=$2" >> "$ENV_FILE"
	fi
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--bind) BIND="$2"; shift ;;
		--port) PORT="$2"; shift ;;
		--interface) IFACE="$2"; shift ;;
		--endpoint) ENDPOINT="$2"; shift ;;
		-h|--help) sed -n '2,11p' "$0"; exit 0 ;;
		*) die "unknown option $1" ;;
	esac
	shift
done

[[ $EUID -eq 0 ]] || die "run as root: sudo bash $0"
[[ "$IFACE" =~ ^[A-Za-z0-9_=+.-]{1,15}$ ]] || die "invalid interface"

# Where gunicorn listens. --bind wins, then whatever the last run stored, then
# every address on $PORT (default 8905).
[[ -n "$BIND" ]] || BIND=$(env_get PRIVATEVPN_BIND)
if [[ -n "$PORT" || -z "$BIND" ]]; then
	[[ -n "$PORT" ]] || PORT=${BIND##*:}
	[[ -n "$PORT" ]] || PORT=8905
	[[ "$PORT" =~ ^[0-9]+$ ]] || die "invalid port"
	BIND_HOST=${BIND%:*}
	BIND="${BIND_HOST:-0.0.0.0}:$PORT"
fi
[[ "$BIND" =~ ^[A-Za-z0-9_.:-]+:[0-9]+$ ]] || die "invalid --bind '$BIND', expected HOST:PORT"
BIND_HOST=${BIND%:*}
PORT=${BIND##*:}
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
WG_CONF="/etc/wireguard/$IFACE.conf"

command -v wg > /dev/null || die "WireGuard is not installed. Install it first (e.g. wireguard-install.sh)."
[[ -f "$WG_CONF" ]] || die "$WG_CONF not found. Use --interface if yours is not wg0."
command -v systemctl > /dev/null || die "systemd is required."

step "Installing packages"
if command -v apt-get > /dev/null; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq python3 python3-venv python3-pip rsync sudo > /dev/null
elif command -v dnf > /dev/null; then
	dnf install -y -q python3 python3-pip rsync sudo
else
	die "unsupported distro: install python3 (with venv), rsync and sudo, then re-run."
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "Python 3.10+ required."

step "Creating user and folders"
id "$APP_USER" &> /dev/null || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
install -d -m 0755 -o root -g root "$APP_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"

step "Copying app to $APP_DIR"
if [[ "$SRC_DIR" != "$APP_DIR" ]]; then
	rsync -a --delete \
		--exclude .git --exclude .venv --exclude .claude --exclude __pycache__ \
		--exclude db.sqlite3 --exclude .secret_key --exclude known_hosts --exclude staticfiles --exclude cache \
		"$SRC_DIR/" "$APP_DIR/"
fi
chown -R root:root "$APP_DIR"

step "Python environment"
[[ -x "$APP_DIR/.venv/bin/python" ]] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt" gunicorn

step "Root helper + sudo rule"
sed 's/\r$//' "$APP_DIR/deploy/privatevpn-helper" > "$HELPER.new"
install -m 0755 -o root -g root "$HELPER.new" "$HELPER"
rm -f "$HELPER.new"
SUDOERS=/etc/sudoers.d/privatevpn
echo "$APP_USER ALL=(root) NOPASSWD: $HELPER" > "$SUDOERS.new"
chmod 0440 "$SUDOERS.new"
visudo -cf "$SUDOERS.new" > /dev/null || die "sudoers rule failed validation"
mv -f "$SUDOERS.new" "$SUDOERS"

# --- addresses ---------------------------------------------------------------
VPN_ADDR=$(awk -F= '/^[[:space:]]*Address[[:space:]]*=/{print $2; exit}' "$WG_CONF" | tr ',' '\n' | grep -m1 '\.' | tr -d ' ' || true)
[[ -n "$VPN_ADDR" ]] || die "no IPv4 Address in $WG_CONF"
VPN_IP=${VPN_ADDR%/*}
if [[ -z "$ENDPOINT" ]]; then
	ENDPOINT=$(grep -m1 '^# ENDPOINT' "$WG_CONF" | awk '{print $3}' || true)
fi
if [[ -z "$ENDPOINT" ]]; then
	ENDPOINT=$(ip -4 route get 1.1.1.1 2> /dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
fi
PORT_SUFFIX=":$PORT"
[[ "$PORT" != "80" ]] || PORT_SUFFIX=""

# Plain HTTP, served by gunicorn itself. Django must accept every address the
# panel can be reached on, so collect them all: the local IPv4 addresses (which
# covers Tailscale, the VPN subnet and the public IP), plus the endpoint.
HOSTS="localhost,127.0.0.1"
while read -r addr; do
	case ",$HOSTS," in *",$addr,"*) ;; *) HOSTS="$HOSTS,$addr" ;; esac
done < <(ip -4 -o addr show scope global 2> /dev/null | awk '{split($4, a, "/"); print a[1]}')
[[ -z "$ENDPOINT" ]] || case ",$HOSTS," in *",$ENDPOINT,"*) ;; *) HOSTS="$HOSTS,$ENDPOINT" ;; esac

ORIGINS=""
for h in ${HOSTS//,/ }; do
	ORIGINS="${ORIGINS:+$ORIGINS,}http://$h$PORT_SUFFIX"
done

PANEL_HOST=$BIND_HOST
[[ "$PANEL_HOST" != "0.0.0.0" ]] || PANEL_HOST=${ENDPOINT:-$VPN_IP}
PANEL_URL="http://$PANEL_HOST$PORT_SUFFIX"

step "Settings ($ENV_FILE)"
if [[ ! -f "$ENV_FILE" ]]; then
	SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')
	cat > "$ENV_FILE" << EOF
PRIVATEVPN_DEBUG=0
PRIVATEVPN_SECRET_KEY=$SECRET
PRIVATEVPN_DATA_DIR=$DATA_DIR
PRIVATEVPN_STATIC_ROOT=$APP_DIR/staticfiles
PRIVATEVPN_TIME_ZONE=Asia/Manila
EOF
	echo "Created $ENV_FILE"
else
	echo "Keeping existing $ENV_FILE"
fi

# Refreshed every run, so an older install picks up the current layout and a
# bare re-run keeps serving on the same address.
env_set PRIVATEVPN_BIND "$BIND"
env_set PRIVATEVPN_HTTPS 0
env_set PRIVATEVPN_ALLOWED_HOSTS "$HOSTS"
env_set PRIVATEVPN_CSRF_ORIGINS "$ORIGINS"
env_set PRIVATEVPN_DEBUG 0
chown root:"$APP_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

manage() {
	# Run manage.py as the app user with the production settings.
	runuser -u "$APP_USER" -- bash -c "set -a; . '$ENV_FILE'; set +a; cd '$APP_DIR'; exec .venv/bin/python manage.py $*"
}

step "Database"
manage migrate --noinput -v 0
manage bootstrap_admin
(set -a; . "$ENV_FILE"; set +a; cd "$APP_DIR"; .venv/bin/python manage.py collectstatic --noinput -v 0)
manage setup_local_server --interface "$IFACE" ${ENDPOINT:+--endpoint "$ENDPOINT"} || \
	echo "WARNING: import failed, finish it in the web UI (Services > Import from server)."

step "Removing nginx front end"
# This panel has no domain name, so there is nothing to get a certificate for.
# gunicorn answers directly instead. Clear out any site a previous run left.
if [[ -f "$NGINX_CONF" ]]; then
	rm -f "$NGINX_CONF"
	command -v nginx > /dev/null && { nginx -t > /dev/null 2>&1 && systemctl reload nginx 2> /dev/null; } || true
	echo "Removed $NGINX_CONF"
else
	echo "Nothing to remove."
fi

step "Firewall"
if command -v ufw > /dev/null && ufw status | grep -q "Status: active"; then
	ufw allow "$PORT"/tcp
elif command -v firewall-cmd > /dev/null && firewall-cmd --state &> /dev/null; then
	firewall-cmd -q --permanent --add-port="$PORT"/tcp && firewall-cmd -q --reload
else
	echo "No ufw/firewalld active; nothing to open."
fi

step "Service"
install -m 0644 "$APP_DIR/deploy/privatevpn.service" /etc/systemd/system/privatevpn.service
systemctl daemon-reload
systemctl enable privatevpn > /dev/null
systemctl restart privatevpn
sleep 2
systemctl is-active --quiet privatevpn || { journalctl -u privatevpn -n 30 --no-pager; die "privatevpn service failed to start"; }

echo
echo "================================================================"
echo " PrivateVPN panel installed."
echo " Open:  $PANEL_URL"
echo " Listening on $BIND, plain HTTP, no nginx."
if [[ "$BIND_HOST" == "0.0.0.0" ]]; then
	echo " Reachable on every address of this server, without encryption."
	echo " Use a private one (Tailscale, VPN, LAN), or re-run with"
	echo " --bind <private-ip>:$PORT to stop it answering publicly."
fi
echo " First login: admin / admin2027 (you must change it right away)"
echo " Logs: journalctl -u privatevpn -f"
echo "================================================================"
