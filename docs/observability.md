# Observability

Sinkhole Responder exposes a small management surface for health, Prometheus,
and structured logs. It defaults to `127.0.0.1:9090` and refuses a non-loopback
bind unless `management.allow_external: true` is explicit.

## Health and metrics

- `GET /healthz` returns `200` with `{"status":"ok"}`.
- `GET /metrics` returns Prometheus text format `0.0.4`.

| Metric | Type | Meaning |
| --- | --- | --- |
| `sinkhole_requests_total{kind,status}` | Counter | Completed public requests by response kind and HTTP status. |
| `sinkhole_request_duration_seconds` | Histogram | Request duration with `0.001`, `0.005`, `0.025`, `0.1`, `0.5`, `1`, `5`, and `+Inf` buckets, plus `_sum` and `_count`. |
| `sinkhole_rules_loaded` | Gauge | Currently compiled response rules. |
| `sinkhole_tls_leaf_cache_entries` | Gauge | Current local-CA leaf cache entries. |
| `sinkhole_build_info{version}` | Gauge | Build identity with a constant value of `1`. |

The Compose deployment publishes management to host loopback only. Do not put
this listener on the public request ports.

## Application and access logs

Logs are structured JSON on standard output. Access records include:

- method, normalized host, and path;
- matched rule, when present;
- response kind and status;
- duration;
- client address.

Query strings are off by default (`logging.log_query: false`) because they often
carry tokens. Client addresses are anonymized to IPv4 `/24` or IPv6 `/48` by
default. Set `logging.access_log: false` to disable access records.

The admin UI keeps a redacted in-memory ring of recent records at `/logs`.

## Opt-in request-body logging

Request-body capture is **disabled by default**. When
`logging.log_request_body: true`, the responder can record a bounded prefix of
selected methods:

- default methods: `POST`;
- optional methods: `PUT`, `PATCH`, and `DELETE`;
- never captured: `GET`, `HEAD`, and `OPTIONS`;
- default cap: `4096` bytes;
- maximum cap: `65536` bytes.

Supported formats are UTF-8 text, JSON, and URL-encoded forms. Common password,
secret, token, session, cookie, credential, and API-key fields in JSON/forms are
replaced with `[REDACTED]`.

These bodies are omitted rather than guessed at:

- multipart;
- compressed or otherwise encoded;
- binary or non-UTF-8;
- invalid JSON or form data;
- unreadable bodies.

Long text and form bodies are marked as truncated. Log fields are:

- `request_body` — captured content;
- `request_body_redacted` — whether known sensitive fields were replaced;
- `request_body_truncated` — whether the cap shortened the body;
- `request_body_omitted` — why capture was skipped.

> [!WARNING]
> Redaction is best-effort. It cannot recognize every secret or personal value,
> especially in free-form text. Captured bodies go to process logs and the
> admin UI's in-memory ring. Use this only temporarily, lock down log access and
> retention, and disable it as soon as troubleshooting is over.

Configure logging through the admin UI, YAML, or the environment variables in
the [configuration reference](configuration.md).

[Back to the documentation index](README.md)

