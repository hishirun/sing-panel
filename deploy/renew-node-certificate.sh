#!/bin/sh
set -eu
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/panel.example.com ] || exit 0
install -o singpanel -g singpanel -m 600 "$RENEWED_LINEAGE/fullchain.pem" /opt/sing-panel/data/tls/fullchain.pem.new
install -o singpanel -g singpanel -m 600 "$RENEWED_LINEAGE/privkey.pem" /opt/sing-panel/data/tls/privkey.pem.new
mv /opt/sing-panel/data/tls/fullchain.pem.new /opt/sing-panel/data/tls/fullchain.pem
mv /opt/sing-panel/data/tls/privkey.pem.new /opt/sing-panel/data/tls/privkey.pem
systemctl restart sing-panel
