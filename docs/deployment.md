# Deployment guide

The default layout uses `80`/`443` for responder traffic, `8080`/`8443` for the
admin UI, and host-loopback `9090` for health and metrics. Every port is
configurable, but blocked clients still expect ordinary web ports, so a
dedicated LAN address is usually the cleanest answer.

## Docker Compose

The supplied [`Dockerfile`](../Dockerfile) builds a non-root `scratch` image
with a read-only root filesystem. [`docker-compose.yml`](../docker-compose.yml)
uses `huntastikus/sinkhole-responder:latest` by default and can still build
locally with `--build`.

```sh
mkdir -p data certs secrets
docker compose up -d
```

The mounts are intentionally simple:

- `/data` is writable and holds configuration plus GUI-managed state;
- `/certs` is read-only for optional certificate/key material;
- `/run/secrets` is read-only for passwords and other secret files.

First start creates `/data/config.yaml` with the admin UI enabled. On Linux,
make sure the host data directory is writable by the chosen UID/GID.
Management is published to `127.0.0.1:9090`, not to the LAN.

### Compose parameters

Copy [`.env.example`](../.env.example) to `.env` and change only what you need.
Every setting below is optional.

| Parameter | Default | Purpose |
| --- | --- | --- |
| `SINKHOLE_IMAGE` | `huntastikus/sinkhole-responder:latest` | Image to pull and run. |
| `SINKHOLE_BUILD_VERSION` | `docker` | Version embedded only for local `--build`. |
| `SINKHOLE_UID`, `SINKHOLE_GID` | `65532`, `65532` | Non-root process identity. Do not use `0`. |
| `SINKHOLE_RESTART_POLICY` | `unless-stopped` | Supervisor policy; needed for the UI's **Restart now** action. |
| `SINKHOLE_DATA_DIR` | `./data` | Host directory mounted read/write at `/data`. |
| `SINKHOLE_CERTS_DIR` | `./certs` | Host certificate/key directory mounted read-only at `/certs`. |
| `SINKHOLE_SECRETS_DIR` | `./secrets` | Host secret directory mounted read-only at `/run/secrets`. |
| `SINKHOLE_DATA_BIND_ADDRESS` | `0.0.0.0` | Host address for data HTTP/HTTPS. |
| `SINKHOLE_ADMIN_BIND_ADDRESS` | `0.0.0.0` | Host address for admin HTTP/HTTPS. |
| `SINKHOLE_MANAGEMENT_BIND_ADDRESS` | `127.0.0.1` | Host address for health/metrics. Keep this on loopback. |
| `SINKHOLE_HTTP_PORT` | `80` | Data HTTP port, inside and outside the container. |
| `SINKHOLE_HTTPS_PORT` | `443` | Data HTTPS port, inside and outside the container. |
| `SINKHOLE_ADMIN_HTTP_PORT` | `8080` | Admin HTTP port. |
| `SINKHOLE_ADMIN_HTTPS_PORT` | `8443` | Admin HTTPS port. |
| `SINKHOLE_MANAGEMENT_PORT` | `9090` | Management port. |

Using the same port inside and outside the container keeps admin redirects
reachable. Nonstandard responder ports require equivalent routing or a
dedicated container address. Ports below `1024` use the image's only added
capability, `NET_BIND_SERVICE`.

Every environment variable in the [configuration reference](configuration.md)
can also be passed through Compose. Environment values override
`/data/config.yaml`; remove an environment variable to return control to YAML.

### Admin password

A secret file is safer than a plain environment value because container
metadata can expose environment variables:

```sh
printf '%s\n' 'replace-with-a-long-password' > secrets/admin_password
chmod 600 secrets/admin_password
```

Add this to `.env`:

```dotenv
SINKHOLE_ADMIN_PASSWORD_FILE=/run/secrets/admin_password
```

The supplied password is authoritative at startup. Changing it rotates the
session-signing key and signs everyone out. With neither password variable,
first-run setup asks for one. `SINKHOLE_ADMIN_PASSWORD` is available for
orchestrators with protected secret injection, but it and the file variable are
mutually exclusive.

### Certificates

Put PEM files in the host certificate directory and use their container paths:

```dotenv
# Existing CA for dynamic local-ca leaves.
SINKHOLE_TLS_MODE=local-ca
SINKHOLE_CA_CERT_FILE=/certs/ca.crt
SINKHOLE_CA_KEY_FILE=/certs/ca.key

# Or one static responder certificate.
# SINKHOLE_TLS_MODE=static
# SINKHOLE_TLS_CERT_FILE=/certs/responder.crt
# SINKHOLE_TLS_KEY_FILE=/certs/responder.key
# SINKHOLE_TLS_HOSTS=blocked.example,ads.example

# Optional separate certificate for the admin listener.
# SINKHOLE_ADMIN_TLS_CERT_FILE=/certs/admin.crt
# SINKHOLE_ADMIN_TLS_KEY_FILE=/certs/admin.key
```

Certificate and key variables are pairs. Keep private keys owner-readable.
Environment configuration supports one static responder pair; use YAML or the
admin UI for multiple host-specific pairs. Without external CA variables,
local-CA mode generates and persists its own CA under `/data`.

Read [TLS and certificates](tls.md) before installing a CA on clients.

## systemd

The supplied [`deploy/sinkhole-responder.service`](../deploy/sinkhole-responder.service)
uses `StateDirectory=sinkhole-responder`. It runs as a dynamic non-root user,
keeps the filesystem read-only, narrows system calls and address families, and
grants only `CAP_NET_BIND_SERVICE` for low ports.

```sh
make build
sudo install -m 0755 bin/sinkhole-responder /usr/local/bin/sinkhole-responder
sudo install -m 0644 deploy/sinkhole-responder.service \
  /etc/systemd/system/sinkhole-responder.service
sudo systemctl daemon-reload
sudo systemctl enable --now sinkhole-responder
```

First start creates `config.yaml`. Open port `8080` to finish setup. After a
manual YAML edit, reload with:

```sh
sudo systemctl reload sinkhole-responder
```

## Bare binary

The application is a single CGO-disabled, embedded binary with no runtime
service dependencies:

```sh
make build
./bin/sinkhole-responder -config ./config.yaml
```

If the selected configuration path does not exist, the binary creates a valid
default file with the admin UI enabled. `-config` defaults to `config.yaml`, and
`-version` prints the version.

A direct non-root Linux process still needs `CAP_NET_BIND_SERVICE` (or an
equivalent service-manager grant) for ports below `1024`. Do not run the whole
application as root just to bind them.

`SIGINT` and `SIGTERM` trigger a graceful shutdown. `SIGHUP` reloads the
configuration; see [Configuration](configuration.md) for what changes live and
what needs a restart.

Helpful Make targets include `make run`, `make compose-up`,
`make compose-down`, and `make test-e2e`.

## Network placement

For a real DNS-routed deployment, review the dedicated-address layouts in
[DNS sinkhole setup](dns-setup.md) and apply the ingress controls from the
[security guide](security.md).

[Back to the documentation index](README.md)
