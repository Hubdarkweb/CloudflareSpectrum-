#!/usr/bin/env bash
set -euo pipefail

# ------------- USER CONFIG (edit before run) -------------
DOMAIN="vpn.example.com"     # your domain / hostname (must point to this VPS)
EMAIL="admin@example.com"    # email for Let's Encrypt notifications (or empty to skip certbot)
CLIENT_NAME="client1"        # name for generated client configs
WG_PORT=51820                # WireGuard UDP port
OVPN_PORT=1194               # OpenVPN TCP port
V2RAY_WS_PORT=443            # Port nginx will listen on for TLS (normally 443)
V2RAY_INTERNAL_PORT=10000    # v2ray binds to 127.0.0.1:<this>
# If you want to use Cloudflare Origin certs, place them at /etc/ssl/cf_origin_cert.pem and /etc/ssl/cf_origin_key.pem
USE_LETSENCRYPT=true         # set false if you plan to use Origin CA certs placed manually
# ---------------------------------------------------------

echo "Starting VPN stack installer for domain: $DOMAIN"
export DEBIAN_FRONTEND=noninteractive

# update + essentials
apt update
apt -y upgrade
apt -y install ca-certificates curl gnupg lsb-release unzip jq

# install UFW
apt -y install ufw

# ---------------- WireGuard install & config ----------------
apt -y install wireguard iptables

SERVER_PRIV_KEY_FILE="/etc/wireguard/server_private.key"
SERVER_PUB_KEY_FILE="/etc/wireguard/server_public.key"
CLIENT_PRIV_KEY_FILE="/etc/wireguard/${CLIENT_NAME}_private.key"
CLIENT_PUB_KEY_FILE="/etc/wireguard/${CLIENT_NAME}_public.key"
WG_CONF="/etc/wireguard/wg0.conf"
WG_CLIENT_DIR="/root/vpn-clients/${CLIENT_NAME}"
mkdir -p "$WG_CLIENT_DIR"

echo "Generating WireGuard keys..."
umask 077
wg genkey | tee "${SERVER_PRIV_KEY_FILE}" | wg pubkey > "${SERVER_PUB_KEY_FILE}"
wg genkey | tee "${CLIENT_PRIV_KEY_FILE}" | wg pubkey > "${CLIENT_PUB_KEY_FILE}"

SERVER_PRIV_KEY=$(cat "${SERVER_PRIV_KEY_FILE}")
SERVER_PUB_KEY=$(cat "${SERVER_PUB_KEY_FILE}")
CLIENT_PRIV_KEY=$(cat "${CLIENT_PRIV_KEY_FILE}")
CLIENT_PUB_KEY=$(cat "${CLIENT_PUB_KEY_FILE}")

cat > "$WG_CONF" <<EOF
[Interface]
Address = 10.10.10.1/24
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
SaveConfig = true
EOF

chmod 600 "$WG_CONF"
systemctl enable wg-quick@wg0
# Do not start yet; we will enable UFW rules first

# WireGuard client config file
cat > "${WG_CLIENT_DIR}/wg-${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = 10.10.10.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = ${SERVER_PUB_KEY}
Endpoint = ${DOMAIN}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 21
EOF

# Add peer to server wg config (so wg0 can pick it up)
cat >> "$WG_CONF" <<EOF

[Peer]
PublicKey = ${CLIENT_PUB_KEY}
AllowedIPs = 10.10.10.2/32
EOF

# ---------------- OpenVPN install & config ----------------
apt -y install openvpn easy-rsa
EASYRSA_DIR="/etc/openvpn/easy-rsa"
mkdir -p "$EASYRSA_DIR"
make-cadir "$EASYRSA_DIR"
pushd "$EASYRSA_DIR" >/dev/null

# Easy-RSA vars: use defaults, build CA and server keys
# Create minimal unattended PKI
./easyrsa init-pki
printf '\n' | ./easyrsa build-ca nopass
./easyrsa gen-req server nopass
./easyrsa sign-req server server <<EOF
yes
EOF
./easyrsa gen-dh
openvpn --genkey --secret ta.key
./easyrsa gen-req ${CLIENT_NAME} nopass
./easyrsa sign-req client ${CLIENT_NAME} <<EOF
yes
EOF

# Copy keys to /etc/openvpn
mkdir -p /etc/openvpn/server
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem ta.key /etc/openvpn/server/
cp pki/issued/${CLIENT_NAME}.crt pki/private/${CLIENT_NAME}.key /root/vpn-clients/${CLIENT_NAME}/
popd >/dev/null

# create server.conf
cat > /etc/openvpn/server/server.conf <<'EOF'
port 1194
proto tcp
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
tls-auth /etc/openvpn/server/ta.key 0
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
EOF

systemctl enable openvpn-server@server
# do not start until firewall configured

# create client.ovpn (embedded certs)
mkdir -p /root/vpn-clients/${CLIENT_NAME}
cat > /root/vpn-clients/${CLIENT_NAME}/client.ovpn <<EOF
client
dev tun
proto tcp
remote ${DOMAIN} ${OVPN_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
key-direction 1
verb 3

<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>
<cert>
$(cat /root/vpn-clients/${CLIENT_NAME}/${CLIENT_NAME}.crt)
</cert>
<key>
$(cat /root/vpn-clients/${CLIENT_NAME}/${CLIENT_NAME}.key)
</key>
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>
EOF

# ---------------- V2Ray install & config ----------------
# Install v2ray (v2fly) official release script
curl -L -s https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh | bash

# create v2ray config
V2_UUID=$(cat /proc/sys/kernel/random/uuid)
mkdir -p /usr/local/etc/v2ray
cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "inbounds": [
    {
      "port": ${V2RAY_INTERNAL_PORT},
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${V2_UUID}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/ws"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF

# ensure v2ray uses this config
systemctl enable v2ray
systemctl restart v2ray || true

# ---------------- NGINX as TLS/WS terminator for V2Ray ----------------
apt -y install nginx

# create nginx server block
NGINX_CONF="/etc/nginx/sites-available/${DOMAIN}.conf"
cat > "${NGINX_CONF}" <<EOF
server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    location /ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${V2RAY_INTERNAL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/${DOMAIN}.conf
rm -f /etc/nginx/sites-enabled/default

# ---------------- TLS certificate (Let's Encrypt) ----------------
if [ "${USE_LETSENCRYPT}" = true ]; then
  apt -y install certbot python3-certbot-nginx
  # attempt to get cert (nginx must be running). Create a minimal HTTP server block for challenge:
  cat > /etc/nginx/sites-available/${DOMAIN}_http <<EOF
server {
  listen 80;
  server_name ${DOMAIN};
  location / {
    return 200 'ok';
  }
}
EOF
  ln -sf /etc/nginx/sites-available/${DOMAIN}_http /etc/nginx/sites-enabled/
  nginx -t && systemctl reload nginx
  certbot --nginx -n --agree-tos --redirect -m "${EMAIL}" -d "${DOMAIN}" || {
    echo "Certbot failed. If you prefer, use Cloudflare Origin CA certs and set USE_LETSENCRYPT=false and supply cert files."
  }
  # reload nginx to pick up certs (site config uses cert paths)
  nginx -t && systemctl reload nginx
else
  echo "Skipping Let's Encrypt. Please place your cert at /etc/letsencrypt/live/${DOMAIN}/fullchain.pem and key at privkey.pem or adjust nginx config."
fi

# ---------------- UFW firewall rules ----------------
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow ${V2RAY_WS_PORT}/tcp     # nginx (V2Ray TLS)
ufw allow ${WG_PORT}/udp           # WireGuard
ufw allow ${OVPN_PORT}/tcp         # OpenVPN (TCP)
# If you use other ports, add here
ufw --force enable

# Start services
systemctl start wg-quick@wg0 || true
systemctl restart openvpn-server@server || true
systemctl restart v2ray || true
systemctl restart nginx || true

# ---------------- Output client credentials & instructions ----------------
CLIENT_DIR="/root/vpn-clients/${CLIENT_NAME}"
mkdir -p "${CLIENT_DIR}/extras"
cat > "${CLIENT_DIR}/README.txt" <<EOF
Client configs for ${CLIENT_NAME}
Domain: ${DOMAIN}

WireGuard client: ${CLIENT_DIR}/wg-${CLIENT_NAME}.conf
OpenVPN client: ${CLIENT_DIR}/client.ovpn
V2Ray (vmess) ID: ${V2_UUID}
V2Ray path: /ws
V2Ray server port: 443 (TLS)
EOF

echo "=== DONE ==="
echo "Client files are in ${CLIENT_DIR}"
echo "V2Ray UUID: ${V2_UUID}"
echo "WireGuard client conf: ${CLIENT_DIR}/wg-${CLIENT_NAME}.conf"
echo "OpenVPN client ovpn: ${CLIENT_DIR}/client.ovpn"

# print short usage reminders
cat <<EOF

NEXT STEPS (manual):
1) In Cloudflare Dashboard -> Spectrum:
   - Add application for WireGuard:
     Protocol: UDP, Port: ${WG_PORT}, DNS hostname: ${DOMAIN}, Origin: <VPS_IP>, Origin port: ${WG_PORT}

   - Add application for OpenVPN:
     Protocol: TCP, Port: ${OVPN_PORT}, DNS hostname: ${DOMAIN}, Origin: <VPS_IP>, Origin port: ${OVPN_PORT}

   - For V2Ray: you can either let Cloudflare forward TCP/443 to origin (Spectrum TCP 443 -> origin 443),
     OR just use Cloudflare's DNS + proxy (orange-cloud) and connect via workers/nginx; for Spectrum set Protocol: TCP, Port: 443.

2) Restrict your VPS firewall to only allow Cloudflare IPs to the service ports (highly recommended).
   Cloudflare publishes their IP list. Fetch it and add UFW rules accordingly.

3) Download client files from /root/vpn-clients/${CLIENT_NAME} via secure transfer (scp).

4) Import WireGuard config into client app, import client.ovpn into OpenVPN client.
   For V2Ray, create a vmess entry:
     address: ${DOMAIN}
     port: 443
     id: ${V2_UUID}
     net: ws
     path: /ws
     tls: tls

REMEMBER: This script configures services and obtains a LetsEncrypt cert (if available).
Be sure to secure backups of private keys and rotate client keys periodically.
EOF
