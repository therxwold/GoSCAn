#!/usr/bin/env bash

# Build versioned GoSCAn release archives for the supported release targets.
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly APP_NAME="goscan"
readonly VERSION_FILE="$SCRIPT_DIR/internal/app/app.go"
readonly DEFAULT_DIST_DIR="$SCRIPT_DIR/dist"
readonly RELEASE_LDFLAGS="-s -w"

# PUBLIC_FILES are included with every binary so downloaded archives remain
# usable without requiring a second copy of the repository.
readonly PUBLIC_FILES=(
  "LICENSE"
  "README.md"
  "config.yml"
  "SPECIFICATIONS.md"
  "CONFIGURATION.md"
  "REMEDIATION.md"
  "CI.md"
  "SECURITY.md"
)

cd "$SCRIPT_DIR"

# Extract the version without relying on GNU-only grep extensions.
version="$(sed -n 's/^const Version string = "\(v[^\"]*\)"$/\1/p' "$VERSION_FILE")"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "GoSCAn release version is missing or invalid in $VERSION_FILE: ${version:-<empty>}" >&2
  exit 1
fi

# RELEASE_TAG is supplied by the tag workflow and prevents a source version from
# being published under a different Git tag.
if [[ -n "${RELEASE_TAG:-}" && "$RELEASE_TAG" != "$version" ]]; then
  echo "GoSCAn source version $version does not match release tag $RELEASE_TAG" >&2
  exit 1
fi

dist_dir="${DIST_DIR:-$DEFAULT_DIST_DIR}"
version_dir="$dist_dir/$version"
case "$version_dir" in
  "$SCRIPT_DIR"/dist/v*|/tmp/*/v*) ;;
  *)
    echo "Refusing unsafe release output directory: $version_dir" >&2
    exit 1
    ;;
esac

for file in "${PUBLIC_FILES[@]}"; do
  if [[ ! -f "$SCRIPT_DIR/$file" ]]; then
    echo "Required release file is missing: $file" >&2
    exit 1
  fi
done

for command in go tar zip; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required release command is unavailable: $command" >&2
    exit 1
  fi
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "A SHA-256 tool is required: sha256sum or shasum" >&2
  exit 1
fi

mkdir -p "$dist_dir"
rm -rf -- "$version_dir"
mkdir -p "$version_dir"

staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/goscan-release.XXXXXX")"
cleanup() {
  rm -rf -- "$staging_dir"
}
trap cleanup EXIT

# package_target builds one target into a temporary archive directory and then
# writes the final archive into the versioned distribution directory.
package_target() {
  local goos="$1"
  local goarch="$2"
  local format="$3"
  local asset_name="$APP_NAME-$version-$goos-$goarch"
  local package_dir="$staging_dir/$asset_name"
  local binary_name="$APP_NAME"
  if [[ "$goos" == "windows" ]]; then
    binary_name+=".exe"
  fi

  mkdir -p "$package_dir"
  echo "Building $goos/$goarch..."
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$RELEASE_LDFLAGS" \
    -o "$package_dir/$binary_name" ./cmd/goscan

  for file in "${PUBLIC_FILES[@]}"; do
    cp "$SCRIPT_DIR/$file" "$package_dir/$file"
  done

  case "$format" in
    tar.gz)
      tar -czf "$version_dir/$asset_name.tar.gz" -C "$staging_dir" "$asset_name"
      ;;
    zip)
      (
        cd "$staging_dir"
        zip -q -r "$version_dir/$asset_name.zip" "$asset_name"
      )
      ;;
    *)
      echo "Unsupported archive format: $format" >&2
      exit 1
      ;;
  esac
}

package_target linux amd64 tar.gz
package_target darwin arm64 tar.gz
package_target windows amd64 zip

(
  cd "$version_dir"
  archives=("$APP_NAME-$version-linux-amd64.tar.gz" "$APP_NAME-$version-darwin-arm64.tar.gz" "$APP_NAME-$version-windows-amd64.zip")
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${archives[@]}" > SHA256SUMS
  else
    shasum -a 256 "${archives[@]}" > SHA256SUMS
  fi
)

echo "Release assets created in $version_dir:"
for asset in "$version_dir"/*; do
  echo "  $(basename "$asset")"
done
