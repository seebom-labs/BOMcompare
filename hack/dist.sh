#!/usr/bin/env bash
# Cross-compiles bomcompare into release archives plus a checksums file.
#
#   hack/dist.sh <version>      e.g. hack/dist.sh 0.1.0
#
# Output (dist/):
#   bomcompare_<version>_<os>_<arch>.tar.gz   (.zip for windows)
#   checksums.txt                             sha256 of every archive
#
# Builds are reproducible: -trimpath, no VCS stamping, archive timestamps and
# ownership taken from SOURCE_DATE_EPOCH (defaults to the HEAD commit time).
set -euo pipefail

VERSION="${1:?usage: hack/dist.sh <version>}"
VERSION="${VERSION#v}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

rm -rf "$DIST"
mkdir -p "$DIST"

for platform in $PLATFORMS; do
  os="${platform%/*}"
  arch="${platform#*/}"
  name="bomcompare_${VERSION}_${os}_${arch}"
  stage="$DIST/$name"
  bin="bomcompare"
  [ "$os" = "windows" ] && bin="bomcompare.exe"

  echo "==> $os/$arch"
  mkdir -p "$stage"
  (cd "$ROOT" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
    -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.version=$VERSION" \
    -o "$stage/$bin" ./cmd/bomcompare)
  cp "$ROOT/LICENSE" "$ROOT/README.md" "$stage/"
  touch -d "@$SOURCE_DATE_EPOCH" "$stage"/*

  if [ "$os" = "windows" ]; then
    (cd "$stage" && zip -qX "$DIST/$name.zip" "$bin" LICENSE README.md)
  else
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$stage" -cf - "$bin" LICENSE README.md | gzip -n > "$DIST/$name.tar.gz"
  fi
  rm -rf "$stage"
done

(cd "$DIST" && sha256sum ./*.tar.gz ./*.zip | sed 's#  \./#  #' > checksums.txt)
echo "==> dist/"
ls -1 "$DIST"
