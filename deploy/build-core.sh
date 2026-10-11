#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=${1:-"$repo/.venv/bin/sing-box"}
mkdir -p "$(dirname "$out")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
go mod download github.com/sagernet/sing-box@v1.14.3
cp -R "$(go env GOMODCACHE)/github.com/sagernet/sing-box@v1.14.3" "$work/source"
chmod -R u+w "$work/source"
cd "$work/source"
git apply "$repo/core-patches/connection-user.patch"
go build -tags with_quic,with_utls,with_v2ray_api,with_clash_api \
  -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.3' \
  -o "$out" ./cmd/sing-box
