#!/bin/sh
# Builds the Windows exe for amd64 and arm64 and packages both with the install scripts into one
# zip in dist/. install.ps1 installs the exe matching the machine's CPU.
# Works on Linux and macOS, no cgo or Windows toolchain needed.
# VERSION is reported in the collector heartbeats, the release workflow sets it to the tag.
set -e

cd "$(dirname "$0")/.."

VERSION=${VERSION:-dev}
OUT=dist/akto-traffic-mirroring-windows
rm -rf dist/akto-traffic-mirroring-windows*
mkdir -p "$OUT"

for ARCH in amd64 arm64; do
  GOOS=windows GOARCH=$ARCH CGO_ENABLED=0 go build \
    -ldflags "-X main.aktoImageVersion=akto-traffic-mirroring-windows-$ARCH:$VERSION" \
    -o "$OUT/mirroring-api-logging-$ARCH.exe" .
done
cp windows/install.ps1 windows/uninstall.ps1 "$OUT/"

(cd dist && zip -qr "$(basename "$OUT").zip" "$(basename "$OUT")")
echo "Built $OUT.zip"
