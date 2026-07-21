# Configuration reference

[`config.example.yaml`](../config.example.yaml) is the living schema example.
Unknown YAML fields are rejected so typos do not quietly become ignored
settings. Durations use Go strings such as `250ms`, `10s`, and `24h`.

Every environment override is optional and takes priority over YAML on startup
and reload. Boolean values must be exactly `true` or `false`.

## Settings

| Section | Key | Default | Environment override and notes |
| --- | --- | --- | --- |
| `listen` | `http` | `['0.0.0.0:80']` | `SINKHOLE_LISTEN_HTTP`, comma-separated; public responder. |
| `listen` | `https` | `['0.0.0.0:443']` | `SINKHOLE_LISTEN_HTTPS`, comma-separated; requires TLS. |
| root | `state_dir` | `''` | `SINKHOLE_STATE_DIR`; empty uses the configuration directory. |
| `admin` | `enabled` | `false` | `SINKHOLE_ADMIN_ENABLED`; seeded appliance config uses `true`. |
| `admin` | `listen` | `0.0.0.0:8080` | `SINKHOLE_ADMIN_LISTEN`; admin HTTP. |
| `admin.tls` | `enabled` | `true` | `SINKHOLE_ADMIN_TLS_ENABLED`. |
| `admin.tls` | `listen` | `0.0.0.0:8443` | `SINKHOLE_ADMIN_TLS_LISTEN`. |
| `admin.tls` | `cert_file` | `''` | `SINKHOLE_ADMIN_TLS_CERT_FILE`; pair with key. |
| `admin.tls` | `key_file` | `''` | `SINKHOLE_ADMIN_TLS_KEY_FILE`; pair with certificate. |
| `admin.tls` | `redirect_http` | `true` | `SINKHOLE_ADMIN_TLS_REDIRECT_HTTP`. |
| `admin` | `session_ttl` | `12h` | `SINKHOLE_ADMIN_SESSION_TTL`. |
| `admin` | `login_rate_per_ip` | `0.2` | `SINKHOLE_ADMIN_LOGIN_RATE_PER_IP`; non-negative. |
| `admin` | `login_burst` | `5` | `SINKHOLE_ADMIN_LOGIN_BURST`; at least `1` when limiting is enabled. |
| `rulepacks` | `enabled` | `[]` | `SINKHOLE_RULEPACKS`, comma-separated; `recommended` is the normal start. |
| `management` | `enabled` | `true` | `SINKHOLE_MANAGEMENT_ENABLED`. |
| `management` | `listen` | `127.0.0.1:9090` | `SINKHOLE_MANAGEMENT_LISTEN`. |
| `management` | `allow_external` | `false` | `SINKHOLE_MANAGEMENT_ALLOW_EXTERNAL`; required for non-loopback bind. |
| `tls` | `mode` | `local-ca` | `SINKHOLE_TLS_MODE`: `disabled`, `static`, or `local-ca`. |
| `tls.static` | `certs` | `[]` | One pair via `SINKHOLE_TLS_CERT_FILE`, `SINKHOLE_TLS_KEY_FILE`, and optional `SINKHOLE_TLS_HOSTS`; use YAML/UI for multiple pairs. |
| `tls.local_ca` | `ca_cert` | `''` | `SINKHOLE_CA_CERT_FILE`; pair with key; empty auto-generates. |
| `tls.local_ca` | `ca_key` | `''` | `SINKHOLE_CA_KEY_FILE`; pair with certificate. |
| `tls.local_ca` | `cache_size` | `1024` | `SINKHOLE_CA_CACHE_SIZE`; at least `1`. |
| `tls.local_ca` | `leaf_ttl` | `24h` | `SINKHOLE_CA_LEAF_TTL`; at least one minute and capped by CA expiry. |
| `defaults` | `status` | `200` | `SINKHOLE_DEFAULTS_STATUS`. |
| `defaults` | `beacon_status` | `200` | `SINKHOLE_DEFAULTS_BEACON_STATUS`. |
| `defaults` | `media_response` | `204` | `SINKHOLE_DEFAULTS_MEDIA_RESPONSE`: `204` or `asset`. |
| `defaults` | `cache_control` | `no-store` | `SINKHOLE_DEFAULTS_CACHE_CONTROL`. |
| `limits` | `max_header_bytes` | `16384` | `SINKHOLE_MAX_HEADER_BYTES`; non-negative. |
| `limits` | `max_body_bytes` | `65536` | `SINKHOLE_MAX_BODY_BYTES`; non-negative. |
| `limits` | `read_timeout` | `10s` | `SINKHOLE_READ_TIMEOUT`; non-negative duration. |
| `limits` | `write_timeout` | `10s` | `SINKHOLE_WRITE_TIMEOUT`; non-negative duration. |
| `limits` | `idle_timeout` | `60s` | `SINKHOLE_IDLE_TIMEOUT`; non-negative duration. |
| `limits` | `rate_per_ip` | `0` | `SINKHOLE_RATE_PER_IP`; requests/second, `0` disables. |
| `limits` | `rate_burst` | `50` | `SINKHOLE_RATE_BURST`; at least `1` when limiting is enabled. |
| `logging` | `level` | `info` | `SINKHOLE_LOG_LEVEL`: `debug`, `info`, `warn`, or `error`. |
| `logging` | `access_log` | `true` | `SINKHOLE_ACCESS_LOG`. |
| `logging` | `log_query` | `false` | `SINKHOLE_LOG_QUERY`; enabling may expose tokens. |
| `logging` | `log_request_body` | `false` | `SINKHOLE_LOG_REQUEST_BODY`; may expose sensitive data. |
| `logging` | `request_body_methods` | `['POST']` | `SINKHOLE_REQUEST_BODY_METHODS`; subset of `POST`, `PUT`, `PATCH`, `DELETE`. |
| `logging` | `request_body_log_max_bytes` | `4096` | `SINKHOLE_REQUEST_BODY_LOG_MAX_BYTES`; `1` through `65536`. |
| `logging` | `anonymize_client` | `true` | `SINKHOLE_ANONYMIZE_CLIENT`. |
| `jsonp` | `enabled` | `false` | `SINKHOLE_JSONP_ENABLED`. |
| `jsonp` | `param` | `callback` | `SINKHOLE_JSONP_PARAM`; non-empty when enabled. |
| root | `rules` | `[]` | Ordered rules documented in [Rules and rulepacks](rules.md). |

Admin authentication adds two optional, startup-only inputs:

- `SINKHOLE_ADMIN_PASSWORD_FILE` — preferred;
- `SINKHOLE_ADMIN_PASSWORD` — for protected orchestrator injection.

They are mutually exclusive and are intentionally not stored in YAML.

## Reload versus restart

Send `SIGHUP` to reload the configuration:

```sh
sudo systemctl reload sinkhole-responder
```

These settings reload immediately:

- rules, rulepacks, defaults, and JSONP;
- logging level, access logs, query/body capture, and anonymization;
- admin session and login-rate tuning.

These need a restart:

- public, admin, TLS, and management listeners;
- TLS mode and certificate material;
- timeouts, header/body limits, and rate limiting;
- state directory.

When an admin-UI save needs a restart, a banner appears on every page.
**Restart now** exits cleanly so Docker or systemd can relaunch the process. A
bare binary without a supervisor simply stops. Reverting the pending change to
the running value clears the banner.

Invalid reloads are logged and the previous working configuration stays active.

## Related guides

- [Deployment](deployment.md) for Compose-specific paths and parameters.
- [TLS and certificates](tls.md) for certificate pair requirements.
- [Observability](observability.md) before enabling query or body logging.
- [Rules and rulepacks](rules.md) for the `rules` schema.

[Back to the documentation index](README.md)

