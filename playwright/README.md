# Browser detector tests

The detector page verifies how browsers handle the sinkhole responder's generic resource placeholders and a site-specific JavaScript rule.

## Prerequisites

From the repository root, build the responder binary:

```sh
make build
```

Then install the test dependencies and Chromium:

```sh
cd playwright
npm ci
npx playwright install chromium
```

## Run

```sh
npx playwright test
```

The Playwright config starts generic and rule-enabled responders on ports 8080 and 8081, plus a static server for `../web/detector.html` on port 8090. The first test proves generic image, script, JSON fetch, iframe, and CORS-preflight checks pass while the vendor-specific `ExampleAds` global remains absent. The second test proves a path-specific response rule supplies that global without breaking the generic checks.

This distinction is intentional: generic responses satisfy resource-load checks, but they cannot reproduce arbitrary vendor behavior. Site-specific rules close that gap when a page expects a particular API or global.

All test origins use `127.0.0.1`, so Chromium's Local Network Access checks do not apply here. Real deployments where a public page requests a responder on a LAN address may be subject to additional Local Network Access restrictions.
