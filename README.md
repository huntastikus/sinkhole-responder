# Sinkhole Responder

Sinkhole Responder works with AdGuard Home, Pi-hole, or any DNS sinkhole that
can return a dedicated responder address for blocked names. It returns tiny,
syntactically valid, harmless HTTP placeholders so pages are less likely to
break and simple resource-load checks can complete without contacting the real
advertising or tracking service.

> **This is not a universal anti-adblock defeat.** It can satisfy some checks
> that only ask whether a resource loaded; it cannot reproduce arbitrary vendor
> behavior or override browser and application security. Read
> [Honest limitations](#honest-limitations) before deployment.

Module: `github.com/huntastikus/sinkhole-responder`

## Contents

- [How it works](#how-it-works)
- [Features](#features)
- [Quick start: GUI appliance](#quick-start-gui-appliance)
- [Admin GUI](#admin-gui)
  - [First-run wizard](#first-run-wizard)
  - [Dashboard](#dashboard)
  - [Configuration and rules](#configuration-and-rules)
  - [Rulepacks](#rulepacks)
  - [Certificate manager](#certificate-manager)
  - [Detector, tools, logs, and health](#detector-tools-logs-and-health)
- [DNS sinkhole configuration](#dns-sinkhole-configuration)
- [Dedicated address guidance](#dedicated-address-guidance)
- [Verification commands](#verification-commands)
- [HTTPS: what DNS redirection cannot solve](#https-what-dns-redirection-cannot-solve)
- [Configurable response rules](#configurable-response-rules)
- [Deployment](#deployment)
- [Security hardening](#security-hardening)
- [Observability](#observability)
- [Configuration reference](#configuration-reference)
- [Honest limitations](#honest-limitations)
- [Build, test, and development](#build-test-and-development)
- [Releases](#releases)
- [License](#license)

## How it works

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

The request path does not proxy, forward, or fetch content from the blocked
origin. The responder makes no application-level outbound connections. Use
numeric listener addresses, as in the example configuration, to avoid needing
DNS resolution for a configured management hostname; deployment firewalls can
deny all initiated egress.

Response selection is deterministic: the first matching configured rule wins;
otherwise `Sec-Fetch-Dest`, `Accept`, the URL extension, and finally an empty
beacon fallback are tried in that order.

## Features

- Embedded valid placeholders for GIF, PNG, SVG, JavaScript, CSS, JSON, HTML,
  text, WAV, and MP4 requests; fonts receive a bodyless `204`.
- Ordered, first-match-wins rules over host, path, method, request headers, and
  query parameters, with inline, base64, file-backed, or embedded responses.
- Three TLS modes: default local CA leaf minting for isolated lab/home clients,
  static certificates, and disabled.
- An authenticated admin GUI with a first-run wizard, live dashboard,
  configuration and rule editors, certificate manager, and troubleshooting
  tools.
- Curated rulepacks that return harmless stubs for common ad and analytics
  libraries, with user-authored rules always taking priority.
- A loopback management listener with health and Prometheus endpoints.
- Structured JSON logs with query logging off and client anonymization on by
  default.
- Graceful `SIGINT`/`SIGTERM` shutdown and safe `SIGHUP` configuration reload.
- Hardened, non-root, read-only `scratch` container packaging.
- A single CGO-disabled Go binary with no runtime service dependencies.

## Quick start: GUI appliance

The v2 appliance has three separate listener planes:

| Plane | Default | Purpose |
| --- | --- | --- |
| Data responder | `0.0.0.0:80`; `0.0.0.0:443` when TLS is enabled | Receives requests for blocked names that the DNS sinkhole redirected here. |
| Admin GUI | `0.0.0.0:8080`; HTTPS on `0.0.0.0:8443` (on by default) | Setup, configuration, rules, certificates, and troubleshooting. |
| Metrics / management | `127.0.0.1:9090` | Prometheus metrics and the health endpoint; loopback-only by default. |

Ports `80` and `443`, like every port below `1024`, require
`CAP_NET_BIND_SERVICE` for a non-root Linux process. The supplied Compose and
systemd deployments grant only that capability.

Docker Compose is the easiest first run:

```sh
mkdir -p data certs secrets
docker compose up -d
```

On Linux, make `./data` writable by numeric UID/GID `65532` before starting if
your container runtime does not arrange bind-mount permissions. The application
seeds `/data/config.yaml` on first launch, with the admin GUI enabled. Open
`http://localhost:8080`, create the admin password, and follow the wizard.

To check the HTTP data responder independently of DNS:

```sh
curl -i --resolve blocked.example:80:127.0.0.1 http://blocked.example/banner.js
```

This tests data port `80`; port `8080` is only the admin GUI. The Compose file
publishes data `80`/`443`, admin `8080`/`8443`, and management `9090` on host
loopback only. Stop it with `docker compose down`.

## Admin GUI

Set `admin.enabled: true`, then browse to `https://<host>:8443`. The HTTP
listener at `http://<host>:8080` redirects there by default. Admin TLS uses a
configured certificate or mints a leaf from the generated local CA for the
requested host or IP — a ~397-day certificate that is renewed automatically
before it expires. On the first visit,
`/setup` asks you to create the admin password and signs you in, then sends you
to the first-run wizard at `/wizard`. Later visits require that password.

### First-run wizard

**1. Welcome — choose the responder address.** The wizard detects LAN
addresses on the host and lets you pick one or enter it manually. Choose the
stable address that DNS clients can reach.

**2. Access mode — choose HTTP or HTTPS.** HTTP-only is simpler and needs no
client trust changes. HTTPS covers sinkholed HTTPS URLs too, but each client
must trust the responder's local CA.

**3. Certificate authority — generate and trust the CA.** If you chose HTTPS,
the wizard generates and activates a local CA, shows its SHA-256 fingerprint,
lets you download the public certificate, and links to the platform-specific
trust guides. The private key stays on the responder and is never offered for
download.

**4. Protection — enable the recommended rulepack.** This turns on the curated
safe-default bundle of harmless stubs for common adblock-detection libraries.
Your own response rules remain first in the evaluation order.

**5. DNS sinkhole — point blocked names here.** The wizard explains the DNS
requirement and prints ready-to-copy AdGuard Home Custom-IP settings for the
selected LAN address. The Help center also covers Pi-hole and other compatible
resolvers. Sinkhole Responder never connects to or modifies the DNS service.

**6. Done — verify the result.** Review the chosen address, access mode, CA,
and recommended protection, then continue to the dashboard, rules editor, or
detector.

### Dashboard

The dashboard at `/` is a live view of responder traffic. It shows total
requests and requests per second, status-class breakdowns, latency p50/p95,
loaded rules, local-CA leaf-certificate cache entries, uptime, and version.
An SVG rate gauge, request-rate sparkline, status history, and latency chart
refresh automatically.

### Configuration and rules

The configuration editor at `/config` provides a structured form for routine
settings and an advanced raw-YAML editor. Every save is parsed and validated
before an atomic replacement; the current file is backed up, the new
configuration is live-reloaded, and a failed reload restores the previous
file. Import / Export can download the current YAML or upload a replacement
for the whole configuration. Imports are backed up first and capped at 1 MiB.

The rules editor at `/rules` lets you add, edit, remove, and drag-reorder
response rules. Its live preview shows which rule would match a sample host,
path, method, destination, and `Accept` header, plus the resulting status,
content type, delay, and body preview.

### Rulepacks

A rulepack is an embedded, curated collection of response rules for a related
ad, analytics, consent, or anti-adblock network. Toggle packs at `/rulepacks`;
changes are saved and live-reloaded just like other configuration changes.
Start with `recommended`: it combines the maintained safe-default set, while
more focused packs are available for targeted setups. User rules always run
before rulepack rules.

### Certificate manager

The certificate manager at `/tls` can upload a matching PEM certificate and
private key for static mode, or generate an in-app local CA for dynamic
certificates. It shows fingerprints and expiry information, lets you download
the CA certificate, and never makes the CA private key downloadable.

> **A trusted CA can impersonate ANY HTTPS site to that client.** Use this only
> in an isolated lab/home environment, only on devices you control, and never
> distribute the CA or install it broadly.

Open the in-app trust guide for
[Windows](/help/trust-windows), [macOS](/help/trust-macos),
[iOS / iPadOS](/help/trust-ios), [Android](/help/trust-android),
[Debian / Ubuntu](/help/trust-debian), [Firefox](/help/trust-firefox), or
[Chrome / Chromium](/help/trust-chrome). These paths are served by the running
admin GUI and include the platform-specific trust-store steps.

### Detector, tools, logs, and health

The detector at `/tools/detector` checks the active rule configuration by
previewing known ad-network requests through the responder's decision engine.
It is a same-origin configuration check: it proves which stubs the current
rules would select, but it does not prove that a client used the intended DNS
or trusts the local CA. For the complete live path, serve or open
`web/detector.html?base=https://responder-address` on the client being tested.
That standalone page makes real requests and distinguishes sinkholed,
not-blocked, unreachable, and skipped results.

The `/tools` page includes **Test a domain**, a network-free dry run showing
the response a host and path would receive, plus an **AdGuard Home config**
generator for users of that resolver. `/logs` shows recent
redacted in-memory logs with a minimum-level filter, record limit, and optional
three-second refresh. The system-health banner reports listeners, TLS,
state-directory writability, recent errors, and rulepack status with colored
health pills.

## DNS sinkhole configuration

Give the responder a stable, dedicated address first. The DNS service must
return that address in blocked-name A and, when configured, AAAA responses;
NXDOMAIN, NODATA, null-address, or REFUSED blocking modes do not send traffic
to Sinkhole Responder.

### AdGuard Home

Configure AdGuard Home as follows:

1. Open **Settings → DNS settings**.
2. Set **Blocking mode** to **Custom IP**.
3. Set **Blocking IPv4** to the responder's static IPv4 address.
4. Set **Blocking IPv6** to the responder's IPv6 address **only if the
   responder is reachable over IPv6**.
5. If there is no reachable IPv6 responder, leave the custom IPv6 value empty
   when the AdGuard Home version permits it. If the UI requires a value, use
   the unspecified address `::`. IPv6 connections to `::` fail rather than
   reach the responder; client fallback to IPv4 is not guaranteed.
6. Use a **low blocked-response TTL** while testing so DNS corrections take
   effect quickly. Increase it only after the setup is proven.
7. Confirm the browser's Secure DNS / DNS-over-HTTPS setting is not bypassing
   AdGuard Home. Also check operating-system and VPN DNS settings.

### Pi-hole

Pi-hole's recommended default `NULL` mode does not route blocked requests to
the responder. Select `IP` blocking mode and force the responder address:

```sh
sudo pihole-FTL --config dns.blocking.mode IP
sudo pihole-FTL --config dns.reply.blocking.force4 true
sudo pihole-FTL --config dns.reply.blocking.IPv4 RESPONDER_IP
```

If the responder is reachable over IPv6, configure `force6` and `IPv6` too.
For an IPv4-only responder, `IP_NODATA_AAAA` avoids returning an unusable IPv6
address. Confirm that client Secure DNS, VPN, or operating-system DNS settings
are not bypassing Pi-hole.

### Other DNS sinkholes

Any resolver is compatible when its blocked response returns the responder's
reachable IPv4 and, if used, IPv6 address. It must preserve the original
hostname so the HTTP `Host` header and TLS SNI reach the responder unchanged.

DNS changes answers; it does not rewrite destination ports. The responder must
therefore be reachable on port `80` for ordinary `http://` URLs and, if HTTPS
is deliberately enabled, on port `443`.

## Dedicated address guidance

The responder needs its own static LAN address. A second service cannot share
the same address and ports `80`/`443` just because its hostname differs. If
the DNS sinkhole's admin UI already occupies those ports, use one of these layouts:

- **Separate VM or small host:** assign a reserved DHCP lease or static address
  and bind the responder directly to `80`/`443`. This has the clearest failure
  and firewall boundaries.
- **Container with macvlan/ipvlan:** give the container its own LAN address, so
  it can listen on `80`/`443` without colliding with the host. Confirm that the
  host can monitor that network; macvlan commonly prevents host-to-container
  communication unless a host-side interface is added.
- **Network namespace:** create a namespace with its own virtual interface and
  LAN address, then run the responder inside it. This is lightweight but
  requires explicit routing, startup, and firewall management.

Do not point blocked domains at the DNS sinkhole address if its UI or another
web server would answer them.

## Verification commands

First verify that the DNS sinkhole returns the responder address. Replace the
uppercase placeholders with real addresses:

```sh
dig blocked.example @DNS_SINKHOLE_IP
```

Then bypass DNS to test the responder itself on production HTTP port `80`:

```sh
curl -v --resolve blocked.example:80:RESPONDER_IP http://blocked.example/banner.js
```

```sh
curl -v --resolve blocked.example:80:RESPONDER_IP -H "Accept: image/avif,image/webp,image/png,*/*" http://blocked.example/ad.png
```

Expected results are `HTTP/1.1 200`, `X-Sinkhole: 1`, a small
`Content-Length`, and the request-appropriate content type:

```text
/banner.js  -> Content-Type: application/javascript; body: /* sinkhole */ plus trailing newline
/ad.png     -> Content-Type: image/gif; 43-byte transparent GIF
```

The image request selects GIF because the `Accept` header's `image/` hint has
higher priority than the `.png` extension. Without that header, `.png` selects
the embedded transparent PNG.

## HTTPS: what DNS redirection cannot solve

DNS redirection alone **cannot transparently answer arbitrary HTTPS domains**.
The browser connects using the original hostname and demands a certificate
valid for that hostname. A certificate for the responder's own name is not
enough.

The three TLS modes are:

- **`disabled`:** no HTTPS listener.
- **`static`:** you provide certificate/key pairs and the hostnames each pair
  serves. It is appropriate only where you legitimately control the names and
  certificates. The first certificate is the fallback when SNI does not match.
- **`local-ca` (default):** a lab/home mode. On first start the responder
  auto-generates a ten-year local CA under `state_dir/tls` (no configuration
  required), then signs and caches a short-lived ECDSA leaf for each valid DNS
  hostname received through SNI. Clients must explicitly trust the supplied CA.

For the guided path, use the first-run wizard or open `/tls` in the admin GUI.
The GUI can generate and activate the local CA, download its public
certificate, link to the trust instructions, upload static certificate/key
pairs, and switch between TLS modes.

### CLI local CA setup

Build the binary and create a five-year CA (the default lifetime):

```sh
make build
./bin/sinkhole-responder create-ca -dir ./ca -cn "Sinkhole Responder Lab CA"
```

That command prints this trust warning before writing anything:

```text
WARNING: You are creating a local certificate authority.
Once trusted by a browser or operating system, this CA lets this tool impersonate ANY HTTPS site to that client.
Use it only in an isolated lab/home environment. Never distribute it or install it system-wide. Protect the private key.
```

It creates `./ca/ca.cert.pem` with mode `0644` and `./ca/ca.key.pem` with mode
`0600`, and refuses to overwrite either file. Configure:

```yaml
listen:
  http: ["0.0.0.0:80"]
  https: ["0.0.0.0:443"]

tls:
  mode: local-ca
  local_ca:
    ca_cert: ./ca/ca.cert.pem
    ca_key: ./ca/ca.key.pem
    cache_size: 1024
    leaf_ttl: 24h
```

The CA private key **must** be readable only by its owner (`0600` or `0400`).
The responder refuses to start if any group or other permission bit is set.
Test the complete SNI and certificate path without disabling verification:

```sh
curl --cacert ./ca/ca.cert.pem --resolve blocked.example:443:RESPONDER_IP https://blocked.example/ad.js
```

Do not use `curl -k` as the normal solution: it disables the verification this
test is meant to exercise.

The responder never auto-installs or auto-trusts the CA. Trust it manually only
inside a dedicated **LAB browser/client profile**, never system-wide. Even with
a trusted local CA, these may still fail:

- certificate pinning or app-specific certificate validation;
- Certificate Transparency expectations;
- Subresource Integrity (SRI) checks against the original body;
- Encrypted Client Hello (ECH) behavior;
- HTTP/3/QUIC-only clients or requests, because the responder serves TCP
  HTTP/1.1 and HTTP/2, not QUIC;
- other application-specific validation of origins, tokens, signatures, or
  response behavior.

## Configurable response rules

Rules are evaluated in file order and the **first match wins**. Every populated
match field in a rule must match (logical AND), and every rule must define at
least one match criterion. A matched rule can override status, media type,
body, headers, or add a bounded delay; omitted response fields inherit the
generic selection.

### Match fields

| Field | Matching behavior |
| --- | --- |
| `host` | Exact, case-insensitive hostname after port removal and IDNA normalization. |
| `host_glob` | Go path-style glob matched against the normalized ASCII/punycode hostname. |
| `path_glob` | Go path-style glob matched against the URL path, never the query string. |
| `path_regex` | Go regular expression matched against the URL path. |
| `method` | Exact HTTP method; supported values are GET, HEAD, POST, PUT, PATCH, DELETE, and OPTIONS. |
| `sec_fetch_dest` | Case-insensitive exact match against `Sec-Fetch-Dest`. |
| `accept` | Case-insensitive substring match against `Accept`. |
| `query` | Map of parameter names to exact first values; an empty expected value checks presence only. |
| `headers` | Map of header names to exact first values; an empty expected value checks presence only. |

### Response fields

| Field | Behavior |
| --- | --- |
| `status` | HTTP status `100`–`599`; `0`/omitted inherits the generic status. |
| `content_type` | Exact `Content-Type`; omitted inherits the generic type or an embedded asset's type. |
| `body` | Inline UTF-8/text body. |
| `body_base64` | Base64-decoded binary body. |
| `body_file` | File loaded once at compile/reload, relative to the config directory, confined there, maximum 1 MiB. |
| `embedded` | Name of a built-in response body. |
| `headers` | Additional response headers, applied after the standard defaults. `Set-Cookie` is always discarded, and body headers are removed for `204`/`304`; avoid overriding `Content-Length` or security headers. |
| `delay_ms` | Response delay from `0` through `10000` milliseconds. |

At most one of `body`, `body_base64`, `body_file`, or `embedded` may be set.
Built-in names are `transparent-gif`, `transparent-png`, `transparent-svg`,
`empty-js`, `empty-css`, `empty-json`, `blank-html`, `empty-text`,
`silent-wav`, and `minimal-mp4`.

### Site-specific JavaScript stub

This is the `ExampleAds` rule exercised by the detector suite:

```yaml
rules:
  - name: example-ad-library
    path_regex: "^/sdk/.+\\.js$"
    response:
      status: 200
      content_type: application/javascript
      body: |
        globalThis.ExampleAds = { loaded: true, ready: function (cb) { if (typeof cb === "function") cb(); } };
```

Site-specific stubs must be built from **observed page behavior**, not guessed
vendor APIs. A wrong stub may hide a failure, create new page errors, or change
application behavior.

### JSONP

JSONP is off by default. When enabled, an unmatched generic script, JSON, or
beacon request with the configured callback parameter receives
`callback({});` as JavaScript. A callback must be at most 128 characters and
match this shape:

```text
identifier
identifier.identifier
```

Identifiers allow ASCII letters, digits after the first character,
underscore, and `$`. Invalid callbacks are ignored and never interpolated;
the normal generic response is returned. Configured rules take priority and
are not JSONP-wrapped.

See [playwright/README.md](playwright/README.md) and `web/detector.html`. The
suite shows which load checks the generic responses satisfy and demonstrates
that the vendor-specific global fails without the rule and passes with it.

## Deployment

The default layout keeps the data responder on `80`/`443`, the admin GUI on
`8080`/`8443`, and metrics on loopback `9090`; every port is configurable.
Choose a dedicated LAN address so the public data ports do not collide with
another web service.

### Docker Compose

The supplied [Dockerfile](Dockerfile) builds a non-root `scratch` image with a
read-only root filesystem. [docker-compose.yml](docker-compose.yml) uses the
published `huntastikus/sinkhole-responder:latest` image by default and remains
buildable locally with `--build`. Configuration and GUI-managed state live in
the writable `/data` volume; operator-provided certificates and secret files
are mounted read-only from `/certs` and `/run/secrets`.

```sh
mkdir -p data certs secrets
docker compose up -d
```

The first run seeds `/data/config.yaml` with the GUI enabled. On Linux, ensure
the bind-mounted `./data` directory is writable by the selected UID/GID.
Management is published to `127.0.0.1:9090` by default, never to the LAN.

#### Container parameters

Copy [.env.example](.env.example) to `.env` to override Compose settings. Every
parameter is optional; unset values use the defaults below.

| Optional parameter | Default | Purpose |
| --- | --- | --- |
| `SINKHOLE_IMAGE` | `huntastikus/sinkhole-responder:latest` | Image to pull and run. |
| `SINKHOLE_BUILD_VERSION` | `docker` | Version embedded only when building locally with `--build`. |
| `SINKHOLE_UID`, `SINKHOLE_GID` | `65532`, `65532` | Numeric non-root process identity; the data directory must be writable by it. Do not use `0`. |
| `SINKHOLE_RESTART_POLICY` | `unless-stopped` | Supervisor policy; keep this enabled for the GUI **Restart now** action. |
| `SINKHOLE_DATA_DIR` | `./data` | Writable host directory mounted at `/data`. |
| `SINKHOLE_CERTS_DIR` | `./certs` | Read-only certificate/key directory mounted at `/certs`. |
| `SINKHOLE_SECRETS_DIR` | `./secrets` | Read-only secret directory mounted at `/run/secrets`. |
| `SINKHOLE_DATA_BIND_ADDRESS` | `0.0.0.0` | Host address for data HTTP/HTTPS. |
| `SINKHOLE_ADMIN_BIND_ADDRESS` | `0.0.0.0` | Host address for admin HTTP/HTTPS. |
| `SINKHOLE_MANAGEMENT_BIND_ADDRESS` | `127.0.0.1` | Host address for health/metrics. Keep loopback unless protected by a trusted network. |
| `SINKHOLE_HTTP_PORT` | `80` | Data HTTP port. |
| `SINKHOLE_HTTPS_PORT` | `443` | Data HTTPS port. |
| `SINKHOLE_ADMIN_HTTP_PORT` | `8080` | Admin HTTP port. |
| `SINKHOLE_ADMIN_HTTPS_PORT` | `8443` | Admin HTTPS port. |
| `SINKHOLE_MANAGEMENT_PORT` | `9090` | Management port. |

Each port is used both inside the container and on the host so admin redirects
always advertise a reachable address. Blocked clients still connect to standard
ports `80`/`443`, so nonstandard data ports require equivalent routing or a
dedicated container address. Ports below `1024` use the image's only added
capability, `NET_BIND_SERVICE`.

All runtime variables in the [configuration reference](#configuration-reference)
are also optional Compose inputs. They override `/data/config.yaml` at every
load; remove a variable to return control to YAML. Listener and state paths are
derived by Compose from the port and volume parameters above.

#### Passwords and certificates

Prefer a file for the admin password because plain environment values are
visible in container metadata:

```sh
printf '%s\n' 'replace-with-a-long-password' > secrets/admin_password
chmod 600 secrets/admin_password
```

Then add this optional setting to `.env`:

```dotenv
SINKHOLE_ADMIN_PASSWORD_FILE=/run/secrets/admin_password
```

The supplied password becomes authoritative at startup. Changing it rotates
the session-signing key and signs out existing sessions. If neither password
variable is set, first-run setup asks for one. `SINKHOLE_ADMIN_PASSWORD` is
supported for orchestrators with protected environment injection, but the two
password variables are mutually exclusive.

Place PEM files beneath the host certificate directory and reference their
container paths. Each certificate and private key is a required pair:

```dotenv
# Use an existing CA to mint per-host leaves in local-ca mode.
SINKHOLE_TLS_MODE=local-ca
SINKHOLE_CA_CERT_FILE=/certs/ca.crt
SINKHOLE_CA_KEY_FILE=/certs/ca.key

# Or serve one static responder certificate (hosts are comma-separated).
# SINKHOLE_TLS_MODE=static
# SINKHOLE_TLS_CERT_FILE=/certs/responder.crt
# SINKHOLE_TLS_KEY_FILE=/certs/responder.key
# SINKHOLE_TLS_HOSTS=blocked.example,ads.example

# Optionally use a separate certificate for the admin HTTPS listener.
# SINKHOLE_ADMIN_TLS_CERT_FILE=/certs/admin.crt
# SINKHOLE_ADMIN_TLS_KEY_FILE=/certs/admin.key
```

Use owner-readable permissions for private keys. Inline PEM private keys are
intentionally unsupported. Environment configuration supports one static
responder pair; configure multiple host-specific pairs in YAML or the admin UI.
Without external CA variables, local-CA mode safely generates and persists its
own CA under `/data`.

### systemd

The supplied [systemd unit](deploy/sinkhole-responder.service) uses
`StateDirectory=sinkhole-responder`, so the configuration and admin state stay
under the service state directory. It runs as a dynamic non-root user with a
strict read-only filesystem policy and grants
`AmbientCapabilities=CAP_NET_BIND_SERVICE` plus a matching capability bounding
set for the low data ports.

```sh
make build
sudo install -m 0755 bin/sinkhole-responder /usr/local/bin/sinkhole-responder
sudo install -m 0644 deploy/sinkhole-responder.service /etc/systemd/system/sinkhole-responder.service
sudo systemctl daemon-reload
sudo systemctl enable --now sinkhole-responder
```

On first start the service seeds its `config.yaml`; open the host on admin port
`8080` to finish setup. Use `sudo systemctl reload sinkhole-responder` after
manual YAML edits.

### Bare binary

The [Makefile](Makefile) builds the embedded application as one binary:

```sh
make build
./bin/sinkhole-responder -config ./config.yaml
```

If the path passed to `-config` does not exist, the binary creates a valid
default configuration there with the admin GUI enabled. `-config` defaults to
`config.yaml`; `-version` prints the version. A direct non-root Linux launch
still needs `CAP_NET_BIND_SERVICE` on the executable (or an equivalent service
manager grant) for ports below `1024`. Do not run the whole application as root
just to bind them. `make compose-up`, `make compose-down`, and `make test-e2e`
wrap the common deployment and browser-test workflows.

## Security hardening

- The image runs as UID/GID `65532`, drops all Linux capabilities except the
  narrowly restored `NET_BIND_SERVICE`, sets `no-new-privileges`, and uses a
  read-only `scratch` root filesystem with `/data` as its writable volume.
- The systemd unit uses a dynamic non-root user, read-only filesystem
  protections, a narrow syscall/address-family policy, and only
  `CAP_NET_BIND_SERVICE` for direct low-port binds.
- The service never forwards to the requested host and needs no initiated
  egress. Enforce that assumption with an egress policy as defense in depth.
- Keep management and metrics on the default loopback listener. Never put
  `/healthz` or `/metrics` on the public request listener. If container
  monitoring requires publishing management, bind the host side to
  `127.0.0.1` only and deliberately enable `management.allow_external` inside
  the container.
- Attacker-controlled Host, path, query, and headers are used only for bounded
  matching and response selection. Request data is never used as a filesystem
  path, shell command, or template. File bodies are loaded from config at
  compile time with traversal and symlink escape checks.

Restrict ingress to trusted LANs. For nftables, add rules like these to the
existing `inet filter input` chain **before** its general reject rule, replacing
the example subnets:

```nftables
ip saddr 192.168.50.0/24 tcp dport { 80, 443 } accept
ip6 saddr fd12:3456:789a::/48 tcp dport { 80, 443 } accept
tcp dport { 80, 443 } drop
```

The final rule drops both untrusted IPv4 and IPv6 traffic to the public ports.
Do not expose `9090`. If HTTP-only, omit `443`; if no IPv6 responder exists,
omit the IPv6 allow rule while keeping the final drop.

For ufw, allow the trusted LAN before denying other traffic (replace the example
subnet):

```sh
sudo ufw allow from 192.168.50.0/24 to any port 80,443 proto tcp
sudo ufw deny 80/tcp
sudo ufw deny 443/tcp
```

Never expose `9090`.

## Observability

The management listener defaults to `127.0.0.1:9090` and refuses a
non-loopback bind unless `management.allow_external: true` is explicit.

- `GET /healthz` returns `200` and `{"status":"ok"}`.
- `GET /metrics` returns Prometheus text format version `0.0.4`.

Metric families are:

| Metric | Type | Meaning |
| --- | --- | --- |
| `sinkhole_requests_total{kind,status}` | counter | Completed public requests by selected response kind and HTTP status. |
| `sinkhole_request_duration_seconds` | histogram | Request duration; exported as `sinkhole_request_duration_seconds_bucket`, `sinkhole_request_duration_seconds_sum`, and `sinkhole_request_duration_seconds_count`, with `0.001`, `0.005`, `0.025`, `0.1`, `0.5`, `1`, `5`, and `+Inf` buckets. |
| `sinkhole_rules_loaded` | gauge | Number of currently compiled response rules. |
| `sinkhole_tls_leaf_cache_entries` | gauge | Current local-CA leaf certificate cache entries. |
| `sinkhole_build_info{version}` | gauge | Build/version identity with constant value `1`. |

Application and access logs are structured JSON on standard output. Access
logs include method, normalized host, path, matched rule when any, response kind,
status, duration, and client address. Query strings are **not logged by
default** (`logging.log_query: false`). Client addresses are anonymized by
default to IPv4 `/24` or IPv6 `/48`. Set `logging.access_log: false` to disable
access logs entirely.

POST body logging is also **disabled by default**. When
`logging.log_post_body: true`, the responder records up to
`logging.post_body_log_max_bytes` bytes (default `4096`, maximum `65536`) from
UTF-8 text, JSON, and URL-encoded form bodies. Common password, secret, token,
session, cookie, credential, and API-key fields in JSON/forms are replaced with
`[REDACTED]`. Multipart, compressed/encoded, binary, invalid JSON/form, and
non-UTF-8 bodies are omitted; long text/form bodies are marked as truncated.
Captured records use `post_body`; `post_body_redacted` and
`post_body_truncated` describe processing, while `post_body_omitted` explains
why an unsafe or unreadable body was not captured.

> **Sensitive-data warning:** body redaction is best-effort and cannot identify
> every secret or personal value, especially in free-form text. Captured bodies
> are written to process logs and retained in the admin UI's in-memory log ring.
> Enable this only temporarily for troubleshooting, restrict log access and
> retention, and disable it immediately afterward.

## Configuration reference

`config.example.yaml` is the living schema example. Unknown YAML fields are
rejected. Durations use Go duration strings such as `250ms`, `10s`, or `24h`.
Every environment override below is optional and takes precedence over YAML on
startup and reload. Boolean values must be exactly `true` or `false`.

| Section | Key | Default | Environment override / notes |
| --- | --- | --- | --- |
| `listen` | `http` | `["0.0.0.0:80"]` | `SINKHOLE_LISTEN_HTTP`, comma-separated; data responder |
| `listen` | `https` | `["0.0.0.0:443"]` | `SINKHOLE_LISTEN_HTTPS`, comma-separated; requires TLS enabled |
| root | `state_dir` | `""` | `SINKHOLE_STATE_DIR`; empty uses the configuration-file directory |
| `admin` | `enabled` | `false` | `SINKHOLE_ADMIN_ENABLED`; seeded appliance config uses `true` |
| `admin` | `listen` | `"0.0.0.0:8080"` | `SINKHOLE_ADMIN_LISTEN`; admin HTTP only |
| `admin.tls` | `enabled` | `true` | `SINKHOLE_ADMIN_TLS_ENABLED` |
| `admin.tls` | `listen` | `"0.0.0.0:8443"` | `SINKHOLE_ADMIN_TLS_LISTEN` |
| `admin.tls` | `cert_file` | `""` | `SINKHOLE_ADMIN_TLS_CERT_FILE`; pair with the key variable |
| `admin.tls` | `key_file` | `""` | `SINKHOLE_ADMIN_TLS_KEY_FILE`; pair with the certificate variable |
| `admin.tls` | `redirect_http` | `true` | `SINKHOLE_ADMIN_TLS_REDIRECT_HTTP` |
| `admin` | `session_ttl` | `"12h"` | `SINKHOLE_ADMIN_SESSION_TTL` |
| `admin` | `login_rate_per_ip` | `0.2` | `SINKHOLE_ADMIN_LOGIN_RATE_PER_IP`; non-negative |
| `admin` | `login_burst` | `5` | `SINKHOLE_ADMIN_LOGIN_BURST`; at least `1` when limiting is enabled |
| `rulepacks` | `enabled` | `[]` | `SINKHOLE_RULEPACKS`, comma-separated; `recommended` is the normal start |
| `management` | `enabled` | `true` | `SINKHOLE_MANAGEMENT_ENABLED` |
| `management` | `listen` | `"127.0.0.1:9090"` | `SINKHOLE_MANAGEMENT_LISTEN` |
| `management` | `allow_external` | `false` | `SINKHOLE_MANAGEMENT_ALLOW_EXTERNAL`; required for non-loopback bind |
| `tls` | `mode` | `"local-ca"` | `SINKHOLE_TLS_MODE`; `disabled`, `static`, or `local-ca` |
| `tls.static` | `certs` | `[]` | One pair via `SINKHOLE_TLS_CERT_FILE`, `SINKHOLE_TLS_KEY_FILE`, and optional comma-separated `SINKHOLE_TLS_HOSTS`; use YAML/UI for multiple pairs |
| `tls.local_ca` | `ca_cert` | `""` | `SINKHOLE_CA_CERT_FILE`; pair with the key variable; empty auto-generates |
| `tls.local_ca` | `ca_key` | `""` | `SINKHOLE_CA_KEY_FILE`; pair with the certificate variable |
| `tls.local_ca` | `cache_size` | `1024` | `SINKHOLE_CA_CACHE_SIZE`; at least `1` |
| `tls.local_ca` | `leaf_ttl` | `"24h"` | `SINKHOLE_CA_LEAF_TTL`; at least one minute and capped by CA expiry |
| `defaults` | `status` | `200` | `SINKHOLE_DEFAULTS_STATUS` |
| `defaults` | `beacon_status` | `200` | `SINKHOLE_DEFAULTS_BEACON_STATUS` |
| `defaults` | `media_response` | `"204"` | `SINKHOLE_DEFAULTS_MEDIA_RESPONSE`; `204` or `asset` |
| `defaults` | `cache_control` | `"no-store"` | `SINKHOLE_DEFAULTS_CACHE_CONTROL` |
| `limits` | `max_header_bytes` | `16384` | `SINKHOLE_MAX_HEADER_BYTES`; non-negative |
| `limits` | `max_body_bytes` | `65536` | `SINKHOLE_MAX_BODY_BYTES`; non-negative |
| `limits` | `read_timeout` | `"10s"` | `SINKHOLE_READ_TIMEOUT`; non-negative duration |
| `limits` | `write_timeout` | `"10s"` | `SINKHOLE_WRITE_TIMEOUT`; non-negative duration |
| `limits` | `idle_timeout` | `"60s"` | `SINKHOLE_IDLE_TIMEOUT`; non-negative duration |
| `limits` | `rate_per_ip` | `0` | `SINKHOLE_RATE_PER_IP`; requests/second, `0` disables |
| `limits` | `rate_burst` | `50` | `SINKHOLE_RATE_BURST`; at least `1` when limiting is enabled |
| `logging` | `level` | `"info"` | `SINKHOLE_LOG_LEVEL`; `debug`, `info`, `warn`, or `error` |
| `logging` | `access_log` | `true` | `SINKHOLE_ACCESS_LOG` |
| `logging` | `log_query` | `false` | `SINKHOLE_LOG_QUERY`; enabling may expose tokens |
| `logging` | `log_post_body` | `false` | `SINKHOLE_LOG_POST_BODY`; opt-in POST body capture; may expose sensitive data |
| `logging` | `post_body_log_max_bytes` | `4096` | `SINKHOLE_POST_BODY_LOG_MAX_BYTES`; capture cap from `1` through `65536` |
| `logging` | `anonymize_client` | `true` | `SINKHOLE_ANONYMIZE_CLIENT` |
| `jsonp` | `enabled` | `false` | `SINKHOLE_JSONP_ENABLED` |
| `jsonp` | `param` | `"callback"` | `SINKHOLE_JSONP_PARAM`; non-empty when enabled |
| root | `rules` | `[]` | Ordered rules described above |

Admin authentication has two additional optional startup-only inputs:
`SINKHOLE_ADMIN_PASSWORD_FILE` (preferred) or `SINKHOLE_ADMIN_PASSWORD`. They
are mutually exclusive and intentionally are not stored in configuration YAML.

Send `SIGHUP` to reload the config. Rules, defaults, JSONP, all logging settings
(`level`, `access_log`, query/body capture, and `anonymize_client`), and the admin
session and login-rate tuning take effect immediately. Public listener addresses,
TLS, management settings, timeouts, body/header limits, rate limiting, the admin
listener and TLS, and the state directory take effect only after a restart. When
a saved change needs a restart, the admin GUI shows a **Restart required** banner
on every page with a **Restart now** button — it exits the process cleanly so the
Docker or systemd supervisor relaunches it (a bare binary with no supervisor
stops instead). Reverting the change back to the running values clears the banner.
Invalid reloads are logged and the previous working configuration stays active.
With systemd, use:

```sh
sudo systemctl reload sinkhole-responder
```

## Honest limitations

Sinkhole Responder answers requests that DNS has **already redirected to it**.
It is not a browser extension, content filter, proxy, or general HTTPS
interceptor. That boundary matters:

- It does **not** block first-party ads or same-domain ad paths when the site's
  real hostname still resolves to the real server.
- It cannot beat detection that never performs a lookup through the configured
  DNS sinkhole—for example, logic bundled into the page, a hard-coded IP, DNS-over-HTTPS
  that bypasses your resolver, or an app's own server-side check.
- HTTPS interception works only after the user deliberately trusts the local
  CA on that client. Without that trust, certificate errors are the correct and
  expected result.
- It may satisfy simple checks that only ask whether a resource loaded, and
  curated stubs can provide a few known globals. It cannot reproduce arbitrary
  vendor behavior or promise that a site's anti-adblock code will be fooled.

Even when a request reaches the responder, it cannot generically supply
vendor-issued cookies or tokens, prove an ad impression to a vendor, reproduce
signed content, satisfy Subresource Integrity hashes, bypass certificate
pinning, or emulate QUIC/HTTP/3-only behavior. CORS credential rules and
application-specific origin, token, signature, or response checks can still
fail.

Modern browsers may classify a public hostname that resolves to a private LAN
address as local-network access and prompt or block the request. Browser
version, request context, and policy matter. Test the actual target browser and
document the observed behavior; this service does not and cannot override
browser security policy.

These limits are fundamental. A site-specific rule may model a small observed
API surface, but it does not contact the vendor and cannot prove an impression,
mint vendor credentials, reproduce signed content, or bypass client-side
security decisions.

## Build, test, and development

The module declares Go `1.26.5`; the Dockerfile and CI currently build with Go
`1.26`. Direct dependencies are intentionally small:

- `gopkg.in/yaml.v3` for strict YAML configuration;
- `golang.org/x/net` for IDNA and HTTP/2 support;
- `golang.org/x/time` for per-client rate limiting.

`golang.org/x/text` is an indirect dependency of `x/net`.

Available Make targets:

| Target | Purpose |
| --- | --- |
| `make build` | Build `./bin/sinkhole-responder`. |
| `make test` | Run all Go tests. |
| `make test-race` | Run all Go tests with the race detector. |
| `make fuzz` | Run all four fuzz targets; set `FUZZTIME`, default `15s` each. |
| `make lint` | Run `go vet ./...` and require clean `gofmt`. |
| `make docker` | Build `sinkhole-responder:dev`; override `VERSION` as needed. |
| `make ca` | Build and create a lab-only CA in `./ca`. |
| `make playwright` | Install locked Node dependencies and run the browser suite. |

Other operational targets are `make run`, `make tidy`, `make compose-up`,
`make compose-down`, and `make clean`.

Run the browser detector suite directly with:

```sh
make build
cd playwright
npm ci
npx playwright install chromium
npx playwright test
```

The suite starts two responders and a static detector page. It proves that
generic image, script, JSON fetch, iframe, and CORS-preflight load checks pass;
the expected `ExampleAds` global fails generically and passes only with the
site-specific rule. Its loopback origins do not test real-world Local Network
Access behavior.

CI runs formatting/vetting, builds, race-enabled tests, four fuzz targets,
Linux `amd64`/`arm64` builds, a Docker build/smoke test, and the Chromium
Playwright suite.

## Releases

Releases use conventional commit titles and an automatically maintained Release
Please PR. A merged `fix:` commit proposes a patch release, `feat:` proposes a
minor release, and a commit with `!` or a `BREAKING CHANGE` footer proposes a
major release after `1.0.0` (or the next minor while the project is pre-1.0).

After releasable work reaches `main` and CI passes, the release workflow creates
or updates the release PR and publishes a multi-platform Docker image for
`linux/amd64` and `linux/arm64`:

```text
huntastikus/sinkhole-responder:X.Y.Z-rc
```

The RC tag is updated when more work is merged for the same proposed release;
the accompanying `sha-<commit>` image tags are immutable. The admin UI displays
RC builds as `vX.Y.Z-RC` and approved releases as `vX.Y.Z`. Test the RC, then
approve the release by reviewing and merging the Release Please PR. That merge
creates the `vX.Y.Z` tag, updates `CHANGELOG.md`, publishes a documented GitHub
Release, and pushes both `huntastikus/sinkhole-responder:X.Y.Z` and `:latest`.
The repository must allow GitHub Actions to create pull requests under
**Settings → Actions → General → Workflow permissions**; the workflow requests
only the `contents: write` and `pull-requests: write` permissions it needs.

## License

Released under the [GNU General Public License, version 2](LICENSE). Copyright
2026 Sinkhole Responder contributors.
