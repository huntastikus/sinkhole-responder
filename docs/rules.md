# Rules and rulepacks

Generic placeholders cover a lot of routine browser requests. Rules handle the
cases that need a specific status, content type, header, body, or small delay.

Rules run in file order and the **first match wins**. Every populated match
field in a rule must match (logical AND), and every rule needs at least one
match criterion. Omitted response fields fall back to generic selection.

## Match fields

| Field | Matching behavior |
| --- | --- |
| `host` | Exact, case-insensitive hostname after port removal and IDNA normalization. |
| `host_glob` | Go path-style glob against the normalized ASCII/punycode hostname. |
| `path_glob` | Go path-style glob against the URL path, never the query string. |
| `path_regex` | Go regular expression against the URL path. |
| `method` | Exact HTTP method: GET, HEAD, POST, PUT, PATCH, DELETE, or OPTIONS. |
| `sec_fetch_dest` | Case-insensitive exact match against `Sec-Fetch-Dest`. |
| `accept` | Case-insensitive substring match against `Accept`. |
| `query` | Parameter names to exact first values; an empty value checks presence only. |
| `headers` | Header names to exact first values; an empty value checks presence only. |

## Response fields

| Field | Behavior |
| --- | --- |
| `status` | HTTP status `100`–`599`; `0` or omitted uses the generic status. |
| `content_type` | Exact `Content-Type`; omitted uses the generic or embedded-asset type. |
| `body` | Inline UTF-8/text body. |
| `body_base64` | Base64-decoded binary body. |
| `body_file` | File loaded at compile/reload, relative to and confined within the config directory, maximum 1 MiB. |
| `embedded` | Name of a built-in response body. |
| `headers` | Extra response headers after defaults. `Set-Cookie` is discarded, and body headers are removed for `204`/`304`. Avoid overriding `Content-Length` or security headers. |
| `delay_ms` | Bounded delay from `0` through `10000` milliseconds. |

Only one of `body`, `body_base64`, `body_file`, or `embedded` may be set.

Built-in asset names are:

- `transparent-gif`
- `transparent-png`
- `transparent-svg`
- `empty-js`
- `empty-css`
- `empty-json`
- `blank-html`
- `empty-text`
- `silent-wav`
- `minimal-mp4`

## Example rule

This is the `ExampleAds` stub used by the detector suite:

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

Build site-specific stubs from **observed page behavior**, not guessed vendor
APIs. A bad stub can hide a real failure, create new page errors, or change
application behavior in surprising ways.

## Rulepacks

Rulepacks are embedded, curated rule collections for related ad, analytics,
consent, or anti-adblock networks. Enable them from `/rulepacks`, YAML, or the
`SINKHOLE_RULEPACKS` environment variable.

`recommended` is the normal starting point. More focused packs are useful when
you know which integrations a site expects. Your custom rules always run before
rulepack rules.

## JSONP

JSONP is disabled by default. When enabled, an unmatched generic script, JSON,
or beacon request with the configured callback parameter receives
`callback({});` as JavaScript.

A callback can be at most 128 characters and must look like:

```text
identifier
identifier.identifier
```

Identifiers use ASCII letters, an initial letter, digits after the first
character, underscore, and `$`. Invalid callbacks are ignored rather than
interpolated. Custom rules take priority and are never JSONP-wrapped.

## Test rules safely

- Use the preview in `/rules` for a detailed sample request.
- Use **Test a domain** under `/tools` for a network-free dry run.
- Use `/tools/detector` to preview the known detector cases.
- Use `web/detector.html?base=https://responder-address` from a client to test
  the actual DNS, network, and trust path.

The browser suite in [`playwright/`](../playwright/README.md) demonstrates
generic image, script, JSON, iframe, and CORS-preflight checks, plus the
site-specific `ExampleAds` behavior.

[Back to the documentation index](README.md)

