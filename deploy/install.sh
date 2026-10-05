#!/bin/bash
# Install or update the PrivateVPN web panel on the WireGuard server.
#
#   sudo bash deploy/install.sh                 # panel reachable only through the VPN
#   sudo bash deploy/install.sh --public        # panel reachable from the internet too
#   sudo bash deploy/install.sh --port 9443 --interface wg0 --endpoint vpn.example.com
#   sudo bash deploy/install.sh --no-nginx --bind 100.64.0.1:8905
#                                               # no nginx, no TLS: gunicorn listens
#                                               # directly on --bind. Only safe when
#                                               # that address is already private
#                                               # (Tailscale, WireGuard, LAN).
#
# Safe to run again after `git pull` to update. Settings in /etc/privatevpn.env,
# the database and the TLS certificate are kept, and the serving mode (nginx or
# not, and the address gunicorn binds) is remembered, so a bare re-run updates
# the code without changing how the panel is reachable.
set -euo pipefail

APP_DIR=/opt/privatevpn
DATA_DIR=/var/lib/privatevpn
CONF_DIR=/etc/privatevpn
ENV_FILE=/etc/privatevpn.env
APP_USER=privatevpn
HELPER=/usr/local/sbin/privatevpn-helper

IFACE=wg0
PORT=8443
ACCESS=vpn
ENDPOINT=""
NGINX=""   # empty = keep whatever the last run chose (nginx for a fresh install)
BIND=""    # empty = derive from NGINX

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

# Read one setting out of the existing env file, without sourcing it.
env_get() { [[ -f "$ENV_FILE" ]] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }

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
		--public) ACCESS=public ;;
		--vpn-only) ACCESS=vpn ;;
		--nginx) NGINX=1 ;;
		--no-nginx) NGINX=0 ;;
		--bind) BIND="$2"; NGINX=0; shift ;;
		--port) PORT="$2"; shift ;;
		--interface) IFACE="$2"; shift ;;
		--endpoint) ENDPOINT="$2"; shift ;;
		-h|--help) sed -n '2,14p' "$0"; exit 0 ;;
		*) die "unknown option $1" ;;
	esac
	shift
done

[[ $EUID -eq 0 ]] || die "run as root: sudo bash $0"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "invalid port"
[[ "$IFACE" =~ ^[A-Za-z0-9_=+.-]{1,15}$ ]] || die "invalid interface"

# No --nginx/--no-nginx given: keep what the last run set up.
if [[ -z "$NGINX" ]]; then
	NGINX=$(env_get PRIVATEVPN_NGINX)
	[[ -n "$NGINX" ]] || NGINX=1
fi
[[ "$NGINX" == "0" || "$NGINX" == "1" ]] || die "PRIVATEVPN_NGINX in $ENV_FILE must be 0 or 1"
if [[ "$NGINX" == "0" ]]; then
	[[ -n "$BIND" ]] || BIND=$(env_get PRIVATEVPN_BIND)
	[[ -n "$BIND" ]] || die "--no-nginx needs --bind HOST:PORT (e.g. --bind 100.64.0.1:8905)"
	[[ "$BIND" =~ ^[A-Za-z0-9_.:-]+:[0-9]+$ ]] || die "invalid --bind '$BIND', expected HOST:PORT"
	PORT=${BIND##*:}
else
	BIND=127.0.0.1:8010
fi
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
WG_CONF="/etc/wireguard/$IFACE.conf"

command -v wg > /dev/null || die "WireGuard is not installed. Install it first (e.g. wireguard-install.sh)."
[[ -f "$WG_CONF" ]] || die "$WG_CONF not found. Use --interface if yours is not wg0."
command -v systemctl > /dev/null || die "systemd is required."

step "Installing packages"
if command -v apt-get > /dev/null; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq python3 python3-venv python3-pip nginx openssl rsync sudo > /dev/null
elif command -v dnf > /dev/null; then
	dnf install -y -q python3 python3-pip nginx openssl rsync sudo
else
	die "unsupported distro: install python3 (with venv), nginx, openssl, rsync and sudo, then re-run."
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "Python 3.10+ required."

step "Creating user and folders"
id "$APP_USER" &> /dev/null || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
install -d -m 0755 -o root -g root "$APP_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
install -d -m 0750 -o root -g root "$CONF_DIR"

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
VPN_NET=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$VPN_ADDR")
if [[ -z "$ENDPOINT" ]]; then
	ENDPOINT=$(grep -m1 '^# ENDPOINT' "$WG_CONF" | awk '{print $3}' || true)
fi
if [[ -z "$ENDPOINT" ]]; then
	ENDPOINT=$(ip -4 route get 1.1.1.1 2> /dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
fi
PORT_SUFFIX=""
[[ "$PORT" == "443" ]] || PORT_SUFFIX=":$PORT"

step "Settings ($ENV_FILE)"
if [[ ! -f "$ENV_FILE" ]]; then
	SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')
	HOSTS="$VPN_IP,localhost,127.0.0.1"
	ORIGINS="https://$VPN_IP$PORT_SUFFIX"
	if [[ -n "$ENDPOINT" ]]; then
		HOSTS="$HOSTS,$ENDPOINT"
		ORIGINS="$ORIGINS,https://$ENDPOINT$PORT_SUFFIX"
	fi
	cat > "$ENV_FILE" << EOF
PRIVATEVPN_DEBUG=0
PRIVATEVPN_HTTPS=1
PRIVATEVPN_SECRET_KEY=$SECRET
PRIVATEVPN_DATA_DIR=$DATA_DIR
PRIVATEVPN_STATIC_ROOT=$APP_DIR/staticfiles
PRIVATEVPN_ALLOWED_HOSTS=$HOSTS
PRIVATEVPN_CSRF_ORIGINS=$ORIGINS
PRIVATEVPN_TIME_ZONE=Asia/Manila
EOF
	echo "Created $ENV_FILE"
else
	echo "Keeping existing $ENV_FILE"
fi
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

step "TLS certificate"
if [[ ! -f "$CONF_DIR/tls.crt" ]]; then
	SAN="IP:$VPN_IP,DNS:localhost"
	if [[ -n "$ENDPOINT" ]]; then
		if [[ "$ENDPOINT" =~ ^[0-9.]+$ ]]; then SAN="$SAN,IP:$ENDPOINT"; else SAN="$SAN,DNS:$ENDPOINT"; fi
	fi
	openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=PrivateVPN" \
		-addext "subjectAltName=$SAN" \
		-keyout "$CONF_DIR/tls.key" -out "$CONF_DIR/tls.crt" 2> /dev/null
	chmod 0600 "$CONF_DIR/tls.key"
	echo "Self-signed certificate created (browser will warn once; accept it)."
else
	echo "Keeping existing certificate"
fi

step "nginx"
if [[ "$ACCESS" == "vpn" ]]; then
	RULES="    # VPN-only: connect to WireGuard first, then open https://$VPN_IP$PORT_SUFFIX\n    allow $VPN_NET;\n    allow 127.0.0.1;\n    deny all;"
else
	RULES="    # Public: reachable from anywhere. Keep strong passwords."
fi
NGINX_CONF=/etc/nginx/conf.d/privatevpn.conf
sed -e "s/__PORT__/$PORT/g" "$APP_DIR/deploy/nginx.conf.template" \
	| awk -v rules="$RULES" '{ if ($0 == "__ACCESS_RULES__") { gsub(/\\n/, "\n", rules); print rules } else print }' \
	> "$NGINX_CONF"
if command -v setsebool > /dev/null && command -v getenforce > /dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
	setsebool -P httpd_can_network_connect 1 || true
	command -v semanage > /dev/null && { semanage port -a -t http_port_t -p tcp "$PORT" 2> /dev/null || true; }
fi
nginx -t
systemctl enable --now nginx > /dev/null
systemctl reload nginx

step "Firewall"
if command -v ufw > /dev/null && ufw status | grep -q "Status: active"; then
	if [[ "$ACCESS" == "vpn" ]]; then ufw allow in on "$IFACE" to any port "$PORT" proto tcp; else ufw allow "$PORT"/tcp; fi
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
if [[ "$ACCESS" == "vpn" ]]; then
	echo " Connect to the VPN, then open:  https://$VPN_IP$PORT_SUFFIX"
else
	echo " Open:  https://${ENDPOINT:-$VPN_IP}$PORT_SUFFIX"
fi
echo " First login: admin / admin2027 (you must change it right away)"
echo " Logs: journalctl -u privatevpn -f"
echo "================================================================"
