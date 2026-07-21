<p align="center">
  <img src="internal/admin/web/logo.svg" width="96" alt="Sinkhole Responder logo">
</p>

<h1 align="center">Sinkhole Responder</h1>

<p align="center">
  A friendly HTTP(S) landing spot for traffic blocked by AdGuard Home, Pi-hole,
  and other DNS sinkholes.
</p>

<p align="center">
  <a href="https://github.com/huntastikus/sinkhole-responder/actions/workflows/ci.yml"><img src="https://github.com/huntastikus/sinkhole-responder/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://hub.docker.com/r/huntastikus/sinkhole-responder"><img src="https://img.shields.io/docker/pulls/huntastikus/sinkhole-responder" alt="Docker pulls"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/huntastikus/sinkhole-responder" alt="GPL-2.0 license"></a>
</p>

Ever block an ad domain only to get broken page elements—or a giant
**“Adblock detected”** wall asking you to whitelist the site? Sinkhole
Responder gives those blocked requests somewhere safe to land. It returns
tiny, harmless placeholders for scripts, images, stylesheets, JSON, HTML, and
media instead of leaving every request to fail messily.

That can keep pages tidier and calm down some of those pesky Adblock pop-ups
that only check whether a resource loaded. It never contacts the real ad or
tracking service.

> [!IMPORTANT]
> This is not a magic anti-adblock switch. It cannot imitate every advertising
> platform, bypass browser security, or satisfy checks that need real vendor
> data. The [honest limitations](docs/limitations.md) are worth reading before
> you deploy it.

## How it works

```text
Browser or app requests a blocked hostname
                    │
                    ▼
       AdGuard Home, Pi-hole, or another
       DNS sinkhole returns this server's IP
                    │
                    ▼
        Sinkhole Responder sends a tiny,
          request-appropriate placeholder
                    │
                    └── never forwards upstream
```

Sinkhole Responder is not a DNS server. Your DNS sinkhole still decides what
to block; this service simply answers the HTTP and HTTPS traffic that arrives
afterward.

## What you get

- Safe built-in placeholders for common browser resource types.
- An authenticated, responsive admin UI with a guided first-run setup.
- Custom rules and curated rulepacks for requests that need more than a generic
  empty response.
- HTTP and optional HTTPS support, including a local CA for controlled devices.
- Live request charts, health checks, Prometheus metrics, and structured logs.
- Multi-platform images for `linux/amd64` and `linux/arm64`.
- A tiny, non-root `scratch` container with a read-only root filesystem.
- No application-level forwarding or fetching from blocked hosts.

## Five-minute start

Docker Compose is the easiest way to try it:

```sh
git clone https://github.com/huntastikus/sinkhole-responder.git
cd sinkhole-responder
mkdir -p data certs secrets
docker compose up -d
```

Or pull the published image directly:

```sh
docker pull huntastikus/sinkhole-responder:latest
```

Then:

1. Open `http://localhost:8080`.
2. Create your admin password and follow the setup wizard.
3. Give the responder a stable LAN address.
4. Configure your DNS sinkhole to return that address for blocked names.
5. Test it:

   ```sh
   curl -i --resolve blocked.example:80:127.0.0.1 \
     http://blocked.example/banner.js
   ```

You should see `HTTP/1.1 200` and `X-Sinkhole: 1`.

> [!NOTE]
> Blocked web traffic normally arrives on ports `80` and `443`, so a real
> deployment usually needs a dedicated LAN address. The admin UI uses
> `8080`/`8443`; health and metrics stay on host loopback port `9090` by
> default.

The complete walkthrough lives in [Getting started](docs/getting-started.md).

## Documentation

| If you want to… | Start here |
| --- | --- |
| Understand the setup from end to end | [Getting started](docs/getting-started.md) |
| Connect AdGuard Home, Pi-hole, or another resolver | [DNS sinkhole setup](docs/dns-setup.md) |
| Deploy with Compose, systemd, or a bare binary | [Deployment guide](docs/deployment.md) |
| Learn the admin interface | [Admin guide](docs/admin-guide.md) |
| Configure HTTPS and the local CA | [TLS and certificates](docs/tls.md) |
| Build custom responses or use rulepacks | [Rules and rulepacks](docs/rules.md) |
| See every YAML and environment setting | [Configuration reference](docs/configuration.md) |
| Lock down the service | [Security guide](docs/security.md) |
| Configure metrics and logs | [Observability](docs/observability.md) |
| Understand what the project cannot do | [Honest limitations](docs/limitations.md) |
| Build, test, contribute, or release | [Development and releases](docs/development.md) |

Browse the complete library from the [documentation index](docs/README.md).
The running admin UI also includes an offline Help center with setup and
platform-specific CA trust guides.

## Image tags

| Tag | Use it for |
| --- | --- |
| `latest` | The newest approved release. |
| `X.Y.Z` | A specific approved release; best for repeatable deployments. |
| `X.Y.Z-rc` | A mutable release candidate to test before approval. |

Images are published on
[Docker Hub](https://hub.docker.com/r/huntastikus/sinkhole-responder) for both
`linux/amd64` and `linux/arm64`.

## A quick reality check

Sinkhole Responder helps only when the request actually reaches it. It will not
fix first-party ads, DNS-over-HTTPS that bypasses your resolver, certificate
pinning, signed content, Subresource Integrity, or application-specific checks.
HTTPS also requires deliberate CA trust on devices you control.

That boundary is intentional: the responder serves local placeholders; it does
not proxy traffic, forge vendor data, or weaken browser security. Read the
[full limitations](docs/limitations.md) and [TLS safety guide](docs/tls.md) for
the details.

## Project links

- [Docker Hub](https://hub.docker.com/r/huntastikus/sinkhole-responder)
- [Releases](https://github.com/huntastikus/sinkhole-responder/releases)
- [Changelog](CHANGELOG.md)
- [Issues and feature requests](https://github.com/huntastikus/sinkhole-responder/issues)
- [Source module](https://github.com/huntastikus/sinkhole-responder):
  `github.com/huntastikus/sinkhole-responder`

## License

Sinkhole Responder is released under the
[GNU General Public License, version 2](LICENSE). Copyright 2026 Sinkhole
Responder contributors.
