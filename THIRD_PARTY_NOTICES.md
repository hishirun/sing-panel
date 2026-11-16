# Third-party notices

The original sing-panel application and Agent code are licensed under
GPL-3.0-only; see [LICENSE](LICENSE). Third-party components and artwork retain
their own copyright and license terms. The project is independent and does not
claim endorsement by sing-box, client application developers, or artwork owners.

## sing-box core

- Upstream: <https://github.com/SagerNet/sing-box/tree/v1.14.3>
- Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
- License: GPL-3.0-or-later. The upstream notice also reserves use of its name
  and claims of association; its complete notice is preserved in
  [LICENSES/sing-box-LICENSE.txt](LICENSES/sing-box-LICENSE.txt).
- This project applies [core-patches/connection-user.patch](core-patches/connection-user.patch)
  to expose the connection identity used for accounting and per-user limits.
- [deploy/build-core.sh](deploy/build-core.sh) and [Dockerfile](Dockerfile)
  identify the upstream version, patch, and build options. When distributing a
  compiled core, provide the corresponding upstream source, this patch, and the
  build materials with the applicable notices; a binary alone is insufficient.

## Surfboard configuration template

`panel/subscription_templates/surfboard.conf` was supplied as a client template
and includes rules from Hackl0us/SS-Rule-Snippet. This configuration resource is
distributed under AGPL-3.0-only, separately from the original panel code.
The full license is in [LICENSES/AGPL-3.0.txt](LICENSES/AGPL-3.0.txt).

- Source: <https://github.com/Hackl0us/SS-Rule-Snippet/blob/6fb5c342fbe3c63a3baa4f0e8bb32046631809f6/%E5%BD%92%E6%A1%A3/Surfboard.conf>
- License revision: <https://github.com/Hackl0us/SS-Rule-Snippet/commit/6fb5c342fbe3c63a3baa4f0e8bb32046631809f6>
- Adaptations: managed subscription URL, injected proxy definitions and groups,
  subscription information, and subscription-domain routing placeholders.

Older upstream documentation refers to CC BY-NC-SA 4.0; the pinned revision
above contains the upstream change to AGPL v3. The upstream attribution is
retained in the template and generated profiles.

## Images, application icons, and names

The images in `panel/static/`, including the Shiro character image and client
icons, are not covered by this project's GPL grant. Sources and attribution are
listed in [panel/static/ASSETS.md](panel/static/ASSETS.md). Copyright and
trademark rights remain with their respective owners. Listing a source does
not establish redistribution permission or grant rights to those assets.
The provenance of the unused `logo.png` and `mascot.svg` is not verified here;
they are also excluded from the original-code license grant.

## Rules, subscriptions, and dependencies

Remote rule sets and icon URLs retain the terms of their publishers. Links to
SagerNet, MetaCubeX, blackmatrix7, Loyalsoldier, and Koolson resources do not
relicense those resources. `panel/geo_catalog.json` is a catalog of upstream
rule-set names, not the compiled rule-set payloads.

Python dependencies are listed in `requirements.txt` and
`agent/requirements.txt`; their installed distributions carry their own license
files. Go dependencies of the core are governed by the pinned upstream module
and its dependency notices.
