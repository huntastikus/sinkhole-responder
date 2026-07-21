# TLS and certificates

HTTPS is the part of this setup that deserves the most care. DNS can redirect a
hostname, but it cannot make a browser trust a different server automatically.

When a client opens `https://blocked.example`, it still expects a certificate
valid for `blocked.example`. A certificate for the responder's own hostname is
not enough.

## TLS modes

Sinkhole Responder supports three modes:

- **`disabled`** — no HTTPS listener. This is the simplest choice when HTTP
  placeholders are enough.
- **`static`** — you provide certificate/key pairs and list the hostnames each
  pair serves. Use this only for names and certificates you legitimately
  control. The first certificate is the fallback when SNI does not match.
- **`local-ca`** — the default home/lab mode. The responder creates a ten-year
  local CA under `state_dir/tls`, then signs and caches a short-lived ECDSA leaf
  for each valid SNI hostname. Clients must explicitly trust the public CA.

The first-run wizard and `/tls` page provide the friendliest setup path. They
can generate and activate the CA, show its fingerprint, download the public
certificate, open the trust instructions, upload static certificate pairs,
and switch modes. The private CA key is never downloadable through the UI.

> [!CAUTION]
> Once trusted, a CA can impersonate any HTTPS site to that client. Install it
> only on devices you control, preferably inside a dedicated lab/browser
> profile. Never distribute the private key or install this CA broadly.

## Automatic local CA

With `tls.mode: local-ca` and empty CA paths, no certificate configuration is
needed. First start creates and stores the CA beneath the state directory. The
admin HTTPS listener can use the same CA to mint a roughly 397-day leaf for the
requested host or IP, renewing it before expiry.

Download the public CA certificate from `/tls` or the platform-specific trust
guide in the running Help center. The guides cover Windows, macOS, iOS/iPadOS,
Android, Debian/Ubuntu, Firefox, and Chrome/Chromium.

## Create a CA from the command line

Build the binary and create a five-year CA, which is the command's default
lifetime:

```sh
make build
./bin/sinkhole-responder create-ca \
  -dir ./ca \
  -cn "Sinkhole Responder Lab CA"
```

The command prints a warning before it writes anything:

```text
WARNING: You are creating a local certificate authority.
Once trusted by a browser or operating system, this CA lets this tool impersonate ANY HTTPS site to that client.
Use it only in an isolated lab/home environment. Never distribute it or install it system-wide. Protect the private key.
```

It writes `./ca/ca.cert.pem` with mode `0644` and `./ca/ca.key.pem` with mode
`0600`. It refuses to overwrite either file.

Configure the pair like this:

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

The private key must be readable only by its owner (`0600` or `0400`). Startup
fails if any group or other permission bit is present.

## Verify HTTPS properly

Test DNS/SNI, leaf generation, and CA verification together:

```sh
curl --cacert ./ca/ca.cert.pem \
  --resolve blocked.example:443:RESPONDER_IP \
  https://blocked.example/ad.js
```

Avoid `curl -k` as the normal test: it disables the certificate verification
you are trying to prove.

## Static certificates

Static mode is useful when you own the names and already have appropriate
certificates. A certificate and private key are always a pair. Environment
configuration supports one responder pair; use YAML or the admin UI for
multiple host-specific pairs.

```yaml
tls:
  mode: static
  static:
    certs:
      - cert_file: /certs/responder.crt
        key_file: /certs/responder.key
        hosts: ["blocked.example", "ads.example"]
```

Keep keys in a read-only certificate mount and use owner-readable permissions.
Inline PEM private keys are intentionally unsupported.

## What can still fail

Even after a client trusts the local CA, a request can fail because of:

- certificate pinning or application-specific validation;
- Certificate Transparency expectations;
- Subresource Integrity checks against the original body;
- Encrypted Client Hello behavior;
- HTTP/3/QUIC-only clients, because the responder serves TCP HTTP/1.1 and
  HTTP/2 rather than QUIC;
- origin, token, signature, cookie, or vendor-specific response checks.

The responder never installs or trusts a CA for you. Those boundaries are
deliberate. Read [Honest limitations](limitations.md) for the broader picture.

[Back to the documentation index](README.md)

