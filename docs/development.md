# Development and releases

## Toolchain

The module declares Go `1.26.5`; the Dockerfile and CI build with Go `1.26`.
Direct dependencies stay intentionally small:

- `gopkg.in/yaml.v3` for strict YAML;
- `golang.org/x/net` for IDNA and HTTP/2;
- `golang.org/x/time` for per-client rate limiting.

`golang.org/x/text` is an indirect dependency of `x/net`.

## Make targets

| Target | Purpose |
| --- | --- |
| `make build` | Build `./bin/sinkhole-responder`. |
| `make test` | Run all Go tests. |
| `make test-race` | Run all Go tests with the race detector. |
| `make fuzz` | Run all four fuzz targets; `FUZZTIME` defaults to `15s` each. |
| `make lint` | Run `go vet ./...` and require clean `gofmt`. |
| `make docker` | Build `sinkhole-responder:dev`; override `VERSION` as needed. |
| `make ca` | Build and create a lab-only CA in `./ca`. |
| `make playwright` | Install locked Node dependencies and run browser tests. |

Other useful targets are `make run`, `make tidy`, `make compose-up`,
`make compose-down`, and `make clean`.

## Browser tests

Run the suite directly with:

```sh
make build
cd playwright
npm ci
npx playwright install chromium
npx playwright test
```

The suite starts two responders and a static detector page. It proves generic
image, script, JSON fetch, iframe, and CORS-preflight behavior. The expected
`ExampleAds` global fails with a generic response and passes with its
site-specific rule.

Loopback test origins do not reproduce real-world Local Network Access policy;
test that separately on the target browser.

## CI

CI checks:

- formatting and `go vet`;
- normal and race-enabled tests;
- four fuzz targets;
- Linux `amd64` and `arm64` builds;
- a Docker build and smoke test;
- Chromium Playwright tests.

## Release process

Release Please maintains a release PR from conventional commit titles:

- `fix:` proposes a patch;
- `feat:` proposes a minor release;
- `!` or a `BREAKING CHANGE` footer proposes a major release after `1.0.0`, or
  the next minor while the project is pre-1.0.

After releasable work reaches `main` and CI passes, the workflow creates or
updates the release PR and publishes a multi-platform RC:

```sh
docker pull huntastikus/sinkhole-responder:X.Y.Z-rc
```

The RC tag is mutable and updates as more work enters the proposed release. The
admin UI displays RC builds as `vX.Y.Z-RC`.

When the RC is ready, review and merge the Release Please PR. That creates the
`vX.Y.Z` Git tag, updates [`CHANGELOG.md`](../CHANGELOG.md), publishes a GitHub
Release, and pushes both stable image tags:

```sh
docker pull huntastikus/sinkhole-responder:X.Y.Z
docker pull huntastikus/sinkhole-responder:latest
```

Approved releases display as `vX.Y.Z` in the admin UI. The release workflow
also adds both pull commands to the GitHub Release notes.

GitHub Actions must be allowed to create pull requests under
**Settings → Actions → General → Workflow permissions**. The release workflow
requests only `contents: write` and `pull-requests: write`.

[Back to the documentation index](README.md)
