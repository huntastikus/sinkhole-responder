# Security guide

Sinkhole Responder is deliberately small and does not need to contact blocked
upstream hosts. Keep the network and process permissions just as narrow.

## Built-in hardening

The container:

- runs as UID/GID `65532`;
- drops every Linux capability, then restores only `NET_BIND_SERVICE` for
  ports below `1024`;
- sets `no-new-privileges`;
- uses a read-only `scratch` root filesystem;
- keeps `/data` as its only writable persistent path.

The systemd unit uses a dynamic non-root user, read-only filesystem controls, a
narrow syscall/address-family policy, and the same single capability for low
ports.

The service never forwards to the requested host and needs no application-level
egress. Enforce that assumption with an egress policy as defense in depth.
Prefer numeric listener addresses as shown in the example configuration so a
configured management hostname does not introduce a DNS dependency.

## Listener boundaries

- Public responder traffic belongs on `80` and optionally `443`.
- Keep admin ports `8080`/`8443` on trusted networks.
- Keep management on `127.0.0.1:9090`.
- Never place `/healthz` or `/metrics` on the public responder listener.

If container monitoring needs the management listener to bind beyond loopback
inside the container, publish the host side to `127.0.0.1` and deliberately set
`management.allow_external: true`. That flag means “non-loopback inside the
container,” not “safe to expose on the internet.”

## Request handling

Attacker-controlled host, path, query, and header values are used only for
bounded matching and response selection. Request data is never treated as a
shell command, template, or arbitrary filesystem path.

File-backed response bodies are loaded during compile/reload, confined to the
configuration directory, protected against traversal and symlink escapes, and
capped at 1 MiB.

## Restrict LAN ingress

For nftables, put rules like these in the existing `inet filter input` chain
**before** its general reject rule. Replace the example networks:

```nftables
ip saddr 192.168.50.0/24 tcp dport { 80, 443 } accept
ip6 saddr fd12:3456:789a::/48 tcp dport { 80, 443 } accept
tcp dport { 80, 443 } drop
```

The final rule drops untrusted IPv4 and IPv6 traffic. Omit `443` for HTTP-only,
and omit the IPv6 allow rule when no IPv6 responder exists—keep the final drop.

The ufw equivalent is:

```sh
sudo ufw allow from 192.168.50.0/24 to any port 80,443 proto tcp
sudo ufw deny 80/tcp
sudo ufw deny 443/tcp
```

Never expose `9090` to an untrusted network.

## Passwords and private keys

- Prefer `SINKHOLE_ADMIN_PASSWORD_FILE` over a plain environment value.
- Mount `/run/secrets` and `/certs` read-only.
- Keep private keys owner-readable.
- Never distribute or expose the local CA private key.
- Treat the public CA as powerful configuration: install it only on controlled
  clients that genuinely need HTTPS placeholders.

See [Deployment](deployment.md) for mount examples and
[TLS and certificates](tls.md) for the trust model.

## Logging and privacy

Query logging and request-body capture are off by default. Client IP addresses
are anonymized by default.

Request-body capture is particularly sensitive. Even with built-in redaction,
logs can contain passwords, tokens, cookies, form values, personal information,
or secrets hidden in free-form text. Enable it only for a short troubleshooting
window, restrict access and retention, then switch it off again.

The complete behavior and omission rules are in [Observability](observability.md).

## Know the boundary

This project is a placeholder responder, not a transparent proxy or universal
anti-adblock bypass. Review [Honest limitations](limitations.md) before exposing
it to a wider network.

[Back to the documentation index](README.md)
