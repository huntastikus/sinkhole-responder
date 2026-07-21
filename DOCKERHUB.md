![Sinkhole Responder logo](https://raw.githubusercontent.com/huntastikus/sinkhole-responder/main/internal/admin/web/logo.svg)

# Sinkhole Responder

**A hardened HTTP(S) placeholder responder for AdGuard Home, Pi-hole, and other DNS sinkholes.**

Sinkhole Responder runs at the dedicated IP address returned for blocked DNS
names. Instead of leaving clients with broken connections, it returns tiny,
valid, harmless placeholders for scripts, images, stylesheets, JSON, HTML,
media, and beacon requests. It includes an authenticated admin interface for
configuration, rules, certificates, diagnostics, and live traffic visibility.

[Source code](https://github.com/huntastikus/sinkhole-responder) ·
[Full documentation](https://github.com/huntastikus/sinkhole-responder/tree/main/docs) ·
[Releases](https://github.com/huntastikus/sinkhole-responder/releases) ·
[Issues](https://github.com/huntastikus/sinkhole-responder/issues)

## Highlights

- Works with AdGuard Home, Pi-hole, or any DNS sinkhole that can return a
  dedicated responder IP for blocked names.
- Serves HTTP and HTTPS placeholders without forwarding requests to blocked
  advertising or tracking services.
- Provides a responsive admin UI, first-run wizard, built-in rulepacks,
  certificate management, health checks, Prometheus metrics, and JSON logs.
- Runs as a non-root user in a minimal `scratch` image with a read-only root
  filesystem and a single narrowly scoped Linux capability.
- Publishes multi-platform images for `linux/amd64` and `linux/arm64`.

> Sinkhole Responder is not a DNS server and does not replace AdGuard Home or
> Pi-hole. It receives HTTP(S) traffic only after your DNS sinkhole redirects a
> blocked hostname to the responder's address.

## Quick start

Pull the current approved release:

```sh
docker pull huntastikus/sinkhole-responder:latest
```

Start a hardened container with persistent state:

```sh
docker run -d \
  --name sinkhole-responder \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp \
  -p 80:80 \
  -p 443:443 \
  -p 8080:8080 \
  -p 8443:8443 \
  -e SINKHOLE_STATE_DIR=/data \
  -e SINKHOLE_ADMIN_ENABLED=true \
  -v sinkhole-responder-data:/data \
  huntastikus/sinkhole-responder:latest
```

Open `https://localhost:8443`, create the administrator password, and complete
the setup wizard. The HTTP admin listener on port `8080` redirects to HTTPS.

For a complete deployment with configurable ports, certificate and secret
mounts, loopback-only management access, and documented environment variables,
use the supplied
[Docker Compose configuration](https://github.com/huntastikus/sinkhole-responder/blob/main/docker-compose.yml).

## Image tags

| Tag | Purpose |
| --- | --- |
| `latest` | Most recent approved release. |
| `X.Y.Z` | Specific approved release, such as `0.2.0`. Recommended for reproducible deployments. |
| `X.Y.Z-rc` | Mutable release candidate for testing before approval. |

All published tags support `linux/amd64` and `linux/arm64`.

## Ports

| Container port | Purpose |
| --- | --- |
| `80/tcp` | HTTP responder traffic from blocked hostnames. |
| `443/tcp` | HTTPS responder traffic from blocked hostnames. |
| `8080/tcp` | Admin HTTP listener; redirects to admin HTTPS by default. |
| `8443/tcp` | Admin HTTPS interface. |
| `9090/tcp` | Optional health and Prometheus listener. Publish to host loopback only. |

Blocked clients normally connect to standard ports `80` and `443`. If these
ports are already occupied, use a dedicated host address or equivalent network
routing instead of exposing the responder on unexpected ports.

## Persistent data, certificates, and secrets

| Container path | Access | Purpose |
| --- | --- | --- |
| `/data` | Read/write | Configuration, generated local CA, GUI-managed state, and logs. |
| `/certs` | Read-only, optional | Operator-provided CA and TLS certificate/key files. |
| `/run/secrets` | Read-only, optional | Admin password and other secret files. |

Prefer `SINKHOLE_ADMIN_PASSWORD_FILE` with a file mounted under `/run/secrets`
instead of placing a password directly in container metadata. See the
[container parameter reference](https://github.com/huntastikus/sinkhole-responder/blob/main/docs/deployment.md#compose-parameters)
for every optional port, listener, TLS, rulepack, logging, and security setting.

## DNS sinkhole setup

Configure your DNS sinkhole to return the Sinkhole Responder host's stable LAN
IPv4 or IPv6 address for blocked names. Product-specific guidance is available
for [AdGuard Home](https://github.com/huntastikus/sinkhole-responder/blob/main/docs/dns-setup.md#adguard-home)
and Pi-hole-compatible deployments in the full documentation.

HTTPS requires controlled clients to trust the responder's local CA. This is
appropriate only for devices you administer. Applications with certificate
pinning will still reject generated certificates, which is expected.

## Security and privacy

- The responder does not proxy or retrieve blocked upstream content.
- Client addresses are anonymized by default, and query-string logging is off
  by default.
- Request-body logging is opt-in. Enabling it can capture passwords, tokens,
  form fields, personal information, and other sensitive data; use it only when
  necessary and protect access to the logs.
- Keep the management listener on host loopback and restrict the admin ports to
  trusted networks.

This project intentionally returns generic placeholders. It may satisfy simple
resource-loaded checks, but it is not a universal anti-adblock bypass and does
not emulate arbitrary third-party services.

## Support and license

Report bugs and request features through
[GitHub Issues](https://github.com/huntastikus/sinkhole-responder/issues).
Sinkhole Responder is released under the
[GNU General Public License v2.0](https://github.com/huntastikus/sinkhole-responder/blob/main/LICENSE).
