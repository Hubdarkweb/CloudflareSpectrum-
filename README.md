Below is a complete **user manual** that sets up on a single Ubuntu 22.04+ VPS:

* WireGuard (UDP)
* OpenVPN (TCP)
* V2Ray (vmess over WebSocket + TLS, with nginx as TLS/WS terminator)
* SSH (left enabled)
* UFW firewall rules
* Automatic client config generation for WireGuard, OpenVPN, and V2Ray (vmess JSON + example QR command)
* Helpful notes for Cloudflare Spectrum wiring (you must enable Spectrum in the Cloudflare dashboard — the script does not configure Cloudflare for you)
* Security hardening hints (restrict origin to Cloudflare IP ranges, enable Full (strict) TLS, use Origin CA if desired)

---

# Quick summary / prerequisites

1. A fresh Ubuntu 22.04+ VPS with root access.
2. A domain name (e.g. `vpn.example.com`) pointing to the VPS.
3. Cloudflare account and your domain added to Cloudflare.

   * For **Spectrum**: you need a plan that supports Spectrum (Business/Enterprise / add-on). Spectrum will proxy raw TCP/UDP from a Cloudflare hostname to your VPS IP/port. (You will configure Spectrum from Cloudflare Dashboard.)
4. (Optional but recommended) Cloudflare Origin CA certificate or Let’s Encrypt cert to secure connections Cloudflare→origin (use Full (strict) in Cloudflare SSL settings).
5. Run the script as root (or via sudo).

---

# What the installer will do

* Install packages: `wireguard`, `openvpn`, `easy-rsa`, `nginx`, `certbot` (optional), `unzip`, `curl`, `jq`.
* Set up WireGuard server + one generated client config (wg-client.conf).
* Set up OpenVPN server + one generated client ovpn (client.ovpn).
* Install V2Ray (v2fly) and configure it to listen on `127.0.0.1:10000` (vmess/ws). Nginx will listen on port 443 and reverse-proxy `/ws` to the v2ray inbound. (TLS via certbot or Origin CA file if you provide.)
* Configure UFW to allow service ports.
* Create client files in `/root/vpn-clients/<clientname>/`.
* Provide instructions to create Cloudflare Spectrum apps to forward the relevant ports (WireGuard UDP, OpenVPN TCP, optionally 443 for other services or V2Ray if you want Cloudflare to forward raw TCP to nginx).
* NOT configure Cloudflare automatically (you must add Spectrum via dashboard).

---

# Installer script

Save this as `install-vpn-stack.sh`, `chmod +x`, edit variables at top, then run as root.


---

# How to use these services with Cloudflare Spectrum (manual steps)

1. Log in to Cloudflare → select your domain → **Spectrum**.
2. Click **Add Application**:

   * Name: `wireguard`
   * Protocol: UDP
   * DNS host: `vpn.example.com` (or your chosen host)
   * Port: `51820` (or your `WG_PORT`)
   * Origin: VPS public IP
   * Origin port: `51820`
3. Repeat for `openvpn`:

   * Protocol: TCP
   * Port: `1194`
   * DNS host: `vpn.example.com` (you can use same host but different port)
4. For V2Ray (if you want Spectrum on 443), add a Spectrum app:

   * Protocol: TCP
   * Port: `443`
   * Origin: VPS public IP
   * Origin port: `443`
   * Or instead rely on Cloudflare’s proxy (orange cloud) for DNS and let Cloudflare terminate TLS (for workers). Spectrum is preferred for raw TCP.

Cloudflare Spectrum will now accept client connections at `vpn.example.com:<port>` and forward them to your VPS.

---

# Client-side configs & quick usage

## WireGuard (client)

File: `wg-client.conf` in `/root/vpn-clients/<client>/wg-client.conf`
Import into WireGuard app (mobile/desktop) or use:

```bash
sudo wg-quick up /path/to/wg-client.conf
```

## OpenVPN (client)

File: `/root/vpn-clients/<client>/client.ovpn`
Import into official OpenVPN client or run:

```bash
openvpn --config client.ovpn
```

## V2Ray (vmess over ws + TLS)

Create a client entry in V2RayN / V2RayNG / other client:

* Address: `vpn.example.com`
* Port: `443`
* ID (UUID): printed at the end of the script (also in `/root/vpn-clients/<client>/README.txt`)
* Network: `ws`
* Path: `/ws`
* TLS: enabled

Example vmess JSON (for clients that accept JSON):

```json
{
  "v": "2",
  "ps": "v2ray-vmess",
  "add": "vpn.example.com",
  "port": "443",
  "id": "PUT-UUID-HERE",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "vpn.example.com",
  "path": "/ws",
  "tls": "tls"
}
```

You can generate a QR using `qrencode` (install first: `apt install qrencode`):

```bash
echo 'vmess://<base64-encoded-json>' | qrencode -o vmess.png
```

(Clients commonly accept a vmess URI or scan the QR.)

## SSH

Use regular ssh:

```bash
ssh user@vpn.example.com
```

(If you put SSH behind Spectrum, add Spectrum app for TCP port 22. Alternatively continue to use direct IP SSH and secure it via key auth and allow only Cloudflare IPs if you front it.)

---

# How to restrict origin to Cloudflare IP list (recommended)

Cloudflare publishes IP lists. Best practice: fetch list and add ufw rules to only allow those IP ranges to ports 22, 443, 1194, 51820. Example process (pseudocode — you must fetch the current list from Cloudflare docs):

```bash
# Example: create a file cloudflare-ips.txt and add CF IPv4 and IPv6 ranges
# Then:
for ip in $(cat cloudflare-ips.txt); do
  ufw allow proto tcp from $ip to any port 443
  ufw allow proto udp from $ip to any port 51820
  ufw allow proto tcp from $ip to any port 1194
done
# then deny the same ports from anywhere else
ufw deny 443/tcp
ufw deny 1194/tcp
ufw deny 51820/udp
```

**DO NOT** use an out-of-date CF IP list — fetch the official list from Cloudflare docs before applying.

---


# Security & operational checklist (must-read)

* Rotate client keys/certs regularly.
* Limit how many clients you give access to; remove unused client config entries on the server.
* Use Cloudflare origin certificate and set SSL/TLS mode to **Full (strict)** for end-to-end TLS.
* Restrict origin ports to Cloudflare IP ranges.
* Monitor logs (`journalctl -u openvpn`, `journalctl -u v2ray`, `wg`, nginx logs).
* Spectrum traffic is billed — watch usage.

---

