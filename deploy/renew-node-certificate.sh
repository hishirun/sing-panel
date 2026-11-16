#!/bin/sh
set -eu
expected_lineage=${PANEL_CERT_LINEAGE:-}
if [ -z "$expected_lineage" ] && [ -r /etc/sing-panel/node-certificate-lineage ]; then
    IFS= read -r expected_lineage < /etc/sing-panel/node-certificate-lineage || true
fi
# Specify the certificate lineage in the root-owned file above or the environment.
# The fallback is an example only. Configuration is data, never sourced shell code.
expected_lineage=${expected_lineage:-/etc/letsencrypt/live/panel.example.com}
[ "${RENEWED_LINEAGE:-}" = "$expected_lineage" ] || exit 0
install -o singpanel -g singpanel -m 600 "$RENEWED_LINEAGE/fullchain.pem" /opt/sing-panel/data/tls/fullchain.pem.new
install -o singpanel -g singpanel -m 600 "$RENEWED_LINEAGE/privkey.pem" /opt/sing-panel/data/tls/privkey.pem.new
mv /opt/sing-panel/data/tls/fullchain.pem.new /opt/sing-panel/data/tls/fullchain.pem
mv /opt/sing-panel/data/tls/privkey.pem.new /opt/sing-panel/data/tls/privkey.pem
systemctl restart sing-panel
if systemctl is-active --quiet nginx; then
    nginx -t
    systemctl reload nginx
fi
