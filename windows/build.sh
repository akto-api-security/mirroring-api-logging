#!/bin/sh
# Builds the Windows exe and packages it with the install scripts into dist/.
# Works on Linux and macOS, no cgo or Windows toolchain needed.
set -e

cd "$(dirname "$0")/.."

OUT=dist/akto-traffic-mirroring-windows-amd64
rm -rf "$OUT" "$OUT.zip"
mkdir -p "$OUT"

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$OUT/mirroring-api-logging.exe" .
cp windows/install.ps1 windows/uninstall.ps1 "$OUT/"

(cd dist && zip -qr "$(basename "$OUT").zip" "$(basename "$OUT")")
echo "Built $OUT.zip"
