# DNS sinkhole setup

Sinkhole Responder works only when the DNS service returns its address for a
blocked name. NXDOMAIN, NODATA, null-address, and REFUSED modes never send the
HTTP request here.

Give the responder a stable, dedicated LAN address before changing DNS.

## AdGuard Home

1. Open **Settings → DNS settings**.
2. Set **Blocking mode** to **Custom IP**.
3. Set **Blocking IPv4** to the responder's static IPv4 address.
4. Set **Blocking IPv6** only when the responder is genuinely reachable over
   IPv6.
5. For an IPv4-only responder, leave the custom IPv6 value empty if your
   AdGuard Home version allows it. If the UI requires a value, `::` prevents
   traffic from reaching an unrelated host, but client fallback to IPv4 is not
   guaranteed.
6. Keep the blocked-response TTL low while testing. Raise it after the path is
   proven.
7. Check browser Secure DNS, operating-system DNS, VPN settings, and any other
   DNS-over-HTTPS path that could bypass AdGuard Home.

## Pi-hole

Pi-hole's default `NULL` mode does not route blocked web requests to a custom
responder. Switch to `IP` mode and force the IPv4 reply:

```sh
sudo pihole-FTL --config dns.blocking.mode IP
sudo pihole-FTL --config dns.reply.blocking.force4 true
sudo pihole-FTL --config dns.reply.blocking.IPv4 RESPONDER_IP
```

If the responder is reachable over IPv6, configure `force6` and `IPv6` too.
For an IPv4-only responder, `IP_NODATA_AAAA` avoids advertising an unusable
IPv6 address. Again, check Secure DNS, VPN, and operating-system DNS settings.

## Other DNS sinkholes

Any resolver is compatible when its blocked reply:

- returns the responder's reachable IPv4 and, when used, IPv6 address;
- preserves the original hostname so the HTTP `Host` header and TLS SNI reach
  the responder unchanged;
- sends clients to the normal web ports, `80` and optionally `443`.

DNS changes addresses, not destination ports. A resolver that cannot provide a
custom blocked address is not enough for this setup.

## Why a dedicated address matters

Two services cannot share the same address and ports `80`/`443` simply because
their hostnames differ. If the DNS sinkhole's own UI already uses those ports,
choose one of these layouts:

- **Separate VM or small host.** Give it a reserved DHCP lease or static
  address and bind the responder directly to `80`/`443`. This is the clearest
  option operationally.
- **Container with macvlan or ipvlan.** Give the container its own LAN address.
  Remember that macvlan often blocks host-to-container communication unless
  you add a host-side interface.
- **Network namespace.** Use a dedicated virtual interface and LAN address.
  This is lightweight, but routing, firewalling, and startup become your job.

Do not point blocked domains at the DNS sinkhole's own address if its admin UI
or another web server would answer the requests.

## Verify the complete path

First, confirm that DNS returns the responder address:

```sh
dig blocked.example @DNS_SINKHOLE_IP
```

Then bypass DNS and test the responder directly:

```sh
curl -v --resolve blocked.example:80:RESPONDER_IP \
  http://blocked.example/banner.js
```

Try a request with an image-oriented `Accept` header too:

```sh
curl -v --resolve blocked.example:80:RESPONDER_IP \
  -H "Accept: image/avif,image/webp,image/png,*/*" \
  http://blocked.example/ad.png
```

Expected results include `HTTP/1.1 200`, `X-Sinkhole: 1`, a small
`Content-Length`, and a suitable content type:

```text
/banner.js  -> application/javascript; /* sinkhole */ plus a trailing newline
/ad.png     -> image/gif; 43-byte transparent GIF
```

The second request selects GIF because the `Accept` header's image hint has
priority over the `.png` extension. Without that header, `.png` selects the
embedded transparent PNG.

For a verified HTTPS check, continue with [TLS and certificates](tls.md).

[Back to the documentation index](README.md)
