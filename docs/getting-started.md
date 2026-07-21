# Getting started

This guide takes you from an empty directory to a working responder, then shows
how the request path fits together.

## Before you begin

You need:

- AdGuard Home, Pi-hole, or another DNS sinkhole that can return a custom IP
  address for blocked names;
- a stable LAN address for Sinkhole Responder;
- ports `80` and, if you choose HTTPS, `443` available on that address;
- Docker Compose for the easiest install, or Go if you prefer a bare binary.

Sinkhole Responder is the HTTP(S) half of the setup. It does not decide which
domains are blocked and it never changes your DNS server for you.

## The request path

```text
Client requests a blocked hostname
            |
            v
DNS sinkhole (AdGuard Home, Pi-hole, or compatible resolver)
            |
            | returns the responder's static LAN IPv4/IPv6
            v
Blocked hostname resolves to the Sinkhole Responder address
            |
            v
Sinkhole Responder returns a tiny placeholder for the request type
            X
            +---- never forwards to the real ad/tracker server
```

The service does not proxy, forward, or fetch content from the blocked origin.
Response selection is deterministic: the first matching custom rule wins;
otherwise `Sec-Fetch-Dest`, `Accept`, the URL extension, and finally an empty
beacon fallback are tried in that order.

Built-in responses cover GIF, PNG, SVG, JavaScript, CSS, JSON, HTML, plain
text, WAV, and MP4 requests. Font requests receive a bodyless `204` by default.

## Listener layout

The appliance separates public responder traffic, administration, and
monitoring:

| Plane | Default | Purpose |
| --- | --- | --- |
| Data responder | `0.0.0.0:80` and `0.0.0.0:443` | Requests for blocked names. |
| Admin UI | `0.0.0.0:8080` and HTTPS on `0.0.0.0:8443` | Setup, configuration, rules, certificates, and troubleshooting. |
| Management | `127.0.0.1:9090` | Prometheus metrics and health; loopback-only by default. |

Low ports need `CAP_NET_BIND_SERVICE` for a non-root process. The supplied
Compose and systemd deployments grant only that capability.

## Start with Docker Compose

```sh
git clone https://github.com/huntastikus/sinkhole-responder.git
cd sinkhole-responder
mkdir -p data certs secrets
docker compose up -d
```

On Linux, make sure `./data` is writable by numeric UID/GID `65532` if your
container runtime does not arrange bind-mount permissions. On first launch the
application creates `/data/config.yaml` and enables the admin UI.

Open `http://localhost:8080`. It redirects to admin HTTPS on port `8443`, where
you can create the administrator password and follow the wizard.

Stop the service with:

```sh
docker compose down
```

For custom ports, external certificates, password files, systemd, or a bare
binary, continue with the [deployment guide](deployment.md).

## Finish the setup

1. Pick a stable responder address in the first-run wizard.
2. Decide whether your controlled clients need HTTPS placeholders.
3. If HTTPS is enabled, generate the local CA and install only its public
   certificate on devices you administer.
4. Enable the `recommended` rulepack as a sensible starting point.
5. Configure the DNS sinkhole to return the responder address for blocked
   names. Follow the [DNS setup guide](dns-setup.md).
6. Run the checks below before rolling it out to more clients.

## Quick verification

Test the HTTP responder without changing DNS:

```sh
curl -i --resolve blocked.example:80:127.0.0.1 \
  http://blocked.example/banner.js
```

Look for:

```text
HTTP/1.1 200
X-Sinkhole: 1
Content-Type: application/javascript
```

The JavaScript body is `/* sinkhole */` plus a trailing newline. Once DNS is
configured, use the end-to-end commands in [DNS setup](dns-setup.md).

## What to read next

- [Admin guide](admin-guide.md) for the UI.
- [TLS and certificates](tls.md) before enabling HTTPS broadly.
- [Rules and rulepacks](rules.md) for site-specific placeholders.
- [Honest limitations](limitations.md) before judging whether the approach
  fits your network.

[Back to the documentation index](README.md)
