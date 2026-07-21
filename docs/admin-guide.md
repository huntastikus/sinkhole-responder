# Admin guide

The admin UI is the easiest way to set up and operate Sinkhole Responder. With
the supplied container configuration, open `http://<host>:8080`; it redirects
to `https://<host>:8443` by default.

The first visit asks you to create an administrator password and then sends you
to the setup wizard. Later visits use the same password. Admin TLS either uses
your configured certificate or mints a roughly 397-day leaf from the local CA,
renewing it automatically before expiry.

## First-run wizard

The wizard walks through six short steps:

1. **Responder address.** Pick a detected LAN address or enter one manually.
   Use an address that stays stable and is reachable by your DNS clients.
2. **Access mode.** HTTP-only is simple. HTTPS also covers sinkholed HTTPS URLs,
   but every participating client must trust the responder's local CA.
3. **Certificate authority.** Generate and activate the local CA, review its
   SHA-256 fingerprint, download the public certificate, and open the relevant
   trust guide. The private key never becomes downloadable.
4. **Protection.** Enable the `recommended` rulepack for a maintained set of
   harmless stubs. Your own rules always take priority.
5. **DNS sinkhole.** Review the ready-to-copy AdGuard Home Custom-IP settings
   or open the Help center for Pi-hole and other compatible resolvers. The
   responder never connects to or modifies your DNS service.
6. **Review.** Confirm the address, access mode, CA, and rulepack, then head to
   the dashboard, rules editor, or detector.

## Dashboard

The dashboard at `/` is the default page after login. It shows:

- total requests and requests per second;
- status-class history;
- p50 and p95 latency;
- loaded rules and local-CA leaf-cache entries;
- uptime and application version;
- a live request gauge, request-rate chart, and latency distribution.

The compact **System green** status stays in the navigation bar. Select it to
see listener, TLS, state-directory, recent-error, and rulepack details.

## Configuration

Open `/config` for the structured settings form or the advanced raw-YAML
editor. Every save is parsed and validated before an atomic replacement. The
current file is backed up first; if reload fails, the previous configuration is
restored.

Import and Export can replace or download the complete YAML configuration.
Imports are backed up and capped at 1 MiB.

Some changes reload immediately, while listeners, TLS, timeouts, rate limits,
and other startup settings need a restart. When that happens, every admin page
shows a **Restart required** banner. **Restart now** exits cleanly so Docker or
systemd can relaunch the process.

## Rules and rulepacks

The rules editor at `/rules` lets you add, edit, remove, and drag-reorder custom
responses. Its preview shows which rule would match a sample host, path, method,
destination, and `Accept` header, along with the resulting status, type, delay,
and body.

Rulepacks are embedded, curated collections for related ad, analytics, consent,
or anti-adblock networks. Toggle them at `/rulepacks`. Start with
`recommended`; add focused packs only when you need them. Custom rules always
run before rulepack rules.

The full matching and response model is in [Rules and rulepacks](rules.md).

## Certificate manager

Open `/tls` to:

- generate or replace the local CA;
- download the public CA certificate;
- inspect fingerprints and expiry dates;
- upload a matching PEM certificate and key for static TLS;
- switch between disabled, static, and local-CA modes.

The CA private key is never offered for download.

> [!CAUTION]
> A trusted CA can impersonate any HTTPS site to that client. Use this feature
> only in an isolated home/lab environment and only on devices you control.

The running Help center includes trust-store guides for Windows, macOS,
iOS/iPadOS, Android, Debian/Ubuntu, Firefox, and Chrome/Chromium. Read
[TLS and certificates](tls.md) for the security model and CLI workflow.

## Detector and tools

The detector at `/tools/detector` previews known ad-network requests through
the active decision engine. It proves which stubs the current rules select; it
does not prove that a client used the intended DNS server or trusts the CA.

For a complete client-side check, serve or open
`web/detector.html?base=https://responder-address`. It makes real requests and
distinguishes sinkholed, not-blocked, unreachable, and skipped results.

The `/tools` page also includes:

- **Test a domain**, a network-free dry run of the response for a host/path;
- an **AdGuard Home config** generator.

## Logs and health

The log viewer at `/logs` shows recent redacted in-memory records with a minimum
level, record limit, and optional three-second refresh. The health banner tracks
listeners, TLS, state-directory writability, recent errors, and rulepack state.

For log fields, Prometheus metrics, and the sensitive-data implications of
request-body capture, see [Observability](observability.md).

[Back to the documentation index](README.md)

