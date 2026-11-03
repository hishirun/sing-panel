# Client subscriptions

The private share URL returns HTML for a browser and a full profile for recognized
client User-Agents. `/subscription` always returns subscription data. An unknown
UA on that endpoint uses the base64 URI format. `?format=singbox|mihomo|surge|surfboard|shadowrocket`
overrides detection; fixed-format links remain available.

- `sing-box.json`: complete modern DNS/TUN/routing profile. Snell requires 1.14+.
  A recognized sing-box 1.12/1.13 UA receives no Snell nodes; older versions receive
  an upgrade error. The previous outbound-only response is now a complete profile.
- `clash.yaml`: Mihomo profile based on the supplied YAML, with concrete node lists
  replacing the regex placeholder. Snell v6/userkey nodes are omitted. VLESS Reality,
  Hysteria2, AnyTLS and compatible Snell v5 (v4 wire format) are exported.
- `surge.conf`: supplied rule-set template with populated proxies/groups and a
  fixed-format managed update URL. Snell v5/v6, AnyTLS and Hysteria2 are included;
  Reality and multi-user Snell are omitted. Use a current Surge version.
- `surfboard.conf`: supplied domain-rule template, populated managed URL and groups.
  Snell v6, Reality, multi-user Snell and Gecko Hysteria2 are omitted. Compatible
  Snell v5 is declared v4. The template-only subscription-info panel is replaced
  by standard subscription usage headers.
- `shadowrocket.txt`: existing base64 node links and user-owned external URI cache.

The template files live under `panel/subscription_templates`. Profile generation
is local: credentials are never submitted to a conversion service. Disabled or
expired users do not receive node credentials. Response headers include usage,
expiry, profile title, update interval, share-page URL and `Vary: User-Agent`;
responses remain `Cache-Control: no-store`. Duplicate/reserved proxy names are
normalized without modifying the stored nodes.

Template compatibility changes: modern sing-box action/DNS syntax; explicit
Mihomo proxy fingerprints instead of removed global fingerprint; loopback-only
DNS listener; no automatic MITM or server-certificate-verification bypass from the
Surge example. Client routing and server routing remain independent.

Checked against sing-box 1.14.3 and Mihomo 1.19.33 configuration validators. Surge,
Surfboard and Shadowrocket output is covered by generation tests and documented
syntax, but was not imported on every client/device.

References:
- https://sing-box.sagernet.org/configuration/outbound/snell/
- https://sing-box.sagernet.org/migration/
- https://wiki.metacubex.one/config/proxies/snell/
- https://manual.nssurge.com/policies/overview.html
- https://getsurfboard.com/docs/profile-format/proxy/external-proxy/snell/
