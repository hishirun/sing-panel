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
  canonical share update URL. Snell v5/v6, AnyTLS and Hysteria2 are included;
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

The share URL is also the canonical subscription URL. Application import icons,
managed-profile updates, the copy button and the QR code all use that exact URL.
The receiving client's HTTP User-Agent selects the profile. Explicit format
endpoints remain available for older subscriptions and nonstandard downloaders.
The operating system must have the selected client installed/registered.

## Shadowsocks / SS2022 / Trojan

SS and SS2022 are exported to sing-box, Mihomo and SIP002 URI lists. Surge and
Surfboard include traditional AEAD and AES-based SS2022 methods; 2022 ChaCha20
is omitted from their INI output. Shared AES-SS2022 credentials use
`serverKey:userKey`; dedicated-port nodes use only the personal key.

Trojan TCP and WebSocket are exported to all five panel formats. gRPC is
exported to sing-box, Mihomo and native URI lists, and omitted from INI formats.
WebSocket path/Host, gRPC service name, TLS SNI and verification settings remain
consistent across formats. Client output never includes the server private key
or another user's credential. See [protocol configuration](protocols.md).

The SS/Trojan matrix is verified with real sing-box TCP and UDP traffic for two
users, including exact payload byte totals and quota removal. INI and URI output
is validated against documented syntax, not every installed client version.

## TUIC / ShadowTLS v3

TUIC v5 is exported to all five formats, with UUID/password, verified TLS SNI
and h3 ALPN. sing-box and Mihomo also preserve congestion and UDP relay settings.
ShadowTLS composites are one visible SS node with a private detour in sing-box,
a shadow-tls SS plugin in Mihomo, and v3 wrapper options in Surge. Shadowrocket
links carry a Base64 JSON `shadow-tls` parameter. Surfboard omits these composites
rather than exporting unusable unwrapped SS entries. ShadowTLS supports TCP only.
The share page copies the complete two-outbound graph; hidden detours never
appear in selectors or increment the visible node count. See [protocols](protocols.md).
