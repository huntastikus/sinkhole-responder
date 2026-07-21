# Honest limitations

Sinkhole Responder can make blocked web requests fail more gracefully. It can
also satisfy some simple “did this resource load?” checks. It cannot make every
site believe that a real ad platform is present—and it should not pretend to.

## The request has to reach the responder

The service answers traffic that DNS has **already redirected** to it. It is not
a browser extension, content filter, DNS server, proxy, or general HTTPS
interceptor.

It cannot help when:

- the ad is first-party content on the site's real hostname;
- the detection logic is bundled directly into the page;
- an app uses a hard-coded IP;
- browser, operating-system, VPN, or application DNS-over-HTTPS bypasses your
  sinkhole;
- a server performs its own check without involving the client DNS path.

## A placeholder is not the real vendor

Generic placeholders and curated stubs can provide small, known responses. They
cannot generally:

- issue vendor cookies or tokens;
- prove an ad impression;
- reproduce signed content;
- match Subresource Integrity hashes;
- emulate arbitrary third-party APIs or JavaScript behavior;
- satisfy application-specific origin, credential, signature, or response
  checks.

A site-specific rule can model a small observed API surface. It still does not
contact the vendor, mint vendor credentials, or turn into the real service.

## HTTPS has hard boundaries

HTTPS placeholders work only after a user deliberately trusts the local CA on
that client. Without trust, certificate errors are correct.

Even with trust, certificate pinning, Certificate Transparency policy,
Encrypted Client Hello, QUIC/HTTP/3-only behavior, CORS credentials, and other
application validation may still fail. The responder serves HTTP/1.1 and
HTTP/2 over TCP, not QUIC.

See [TLS and certificates](tls.md) before enabling local-CA mode.

## Browsers protect local networks

Modern browsers may treat a public hostname resolving to a private LAN address
as local-network access. Depending on the browser version, request context, and
policy, the browser may prompt or block the request.

Test the actual browser and device you care about. Sinkhole Responder cannot
and will not override browser security policy.

## About those pesky Adblock pop-ups

Some pop-ups simply check whether a script or image loaded. A harmless
placeholder may satisfy that check. Others expect real globals, tokens,
signatures, cookies, network behavior, or server-side proof. Those will still
spot the difference.

The project aims for cleaner failure and a few honest, targeted compatibility
stubs—not a promise to defeat every anti-adblock system.

[Back to the documentation index](README.md)

