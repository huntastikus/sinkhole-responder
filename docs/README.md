# Sinkhole Responder documentation

Welcome to the detailed docs. The main README gets you running quickly; this
directory keeps the deeper operational and technical material close at hand.

## Start here

- [Getting started](getting-started.md) — how the pieces fit together, the
  listener layout, first launch, and a basic end-to-end check.
- [DNS sinkhole setup](dns-setup.md) — AdGuard Home, Pi-hole, other resolvers,
  dedicated-address layouts, and verification commands.
- [Deployment guide](deployment.md) — Docker Compose, container parameters,
  passwords, certificates, systemd, and bare-binary installs.

## Use the responder

- [Admin guide](admin-guide.md) — the wizard, dashboard, configuration editor,
  rulepacks, certificates, detector, tools, logs, and health banner.
- [TLS and certificates](tls.md) — TLS modes, local CA setup, trust boundaries,
  and a full verified HTTPS test.
- [Rules and rulepacks](rules.md) — matching, responses, embedded assets,
  site-specific stubs, and JSONP.
- [Configuration reference](configuration.md) — every YAML option and
  environment override, plus reload and restart behavior.

## Run it safely

- [Security guide](security.md) — container and systemd hardening, ingress
  examples, secret handling, and network boundaries.
- [Observability](observability.md) — health, Prometheus metrics, JSON logs,
  anonymization, and opt-in request-body capture.
- [Honest limitations](limitations.md) — what a DNS-routed placeholder can and
  cannot solve.

## Work on the project

- [Development and releases](development.md) — toolchain, Make targets,
  browser tests, CI, versioning, RCs, and approved releases.

The running admin interface also serves an offline Help center. It includes
platform-specific CA trust instructions for Windows, macOS, iOS/iPadOS,
Android, Debian/Ubuntu, Firefox, and Chrome/Chromium.

[Back to the project README](../README.md)

