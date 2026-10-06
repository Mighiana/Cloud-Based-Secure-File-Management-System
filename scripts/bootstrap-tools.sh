#!/usr/bin/env bash
# Installs pinned, checksum-verified tool versions into .tools/ (no sudo, no AWS credentials).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.tools/bin"
VENV="$ROOT/.tools/venv"
CHECKOV_VENV="$ROOT/.tools/checkov-venv"
mkdir -p "$BIN"

TERRAFORM_VERSION=1.9.8
TFLINT_VERSION=0.53.0
SHELLCHECK_VERSION=0.10.0
CHECKOV_VERSION=3.2.256

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64; sc_arch=x86_64 ;;
  arm64 | aarch64) arch=arm64; sc_arch=aarch64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# SHA-256 values from each project's release (terraform SHA256SUMS, tflint checksums.txt, shellcheck assets).
expected() {
  case "$1" in
    terraform_linux_amd64) echo 186e0145f5e5f2eb97cbd785bc78f21bae4ef15119349f6ad4fa535b83b10df8 ;;
    terraform_linux_arm64) echo f85868798834558239f6148834884008f2722548f84034c9b0f62934b2d73ebb ;;
    terraform_darwin_amd64) echo be591e8c59c49d0cfbc7664d24910a4b43840b89d0a4bbca662149bbf0397e91 ;;
    terraform_darwin_arm64) echo 873d7b925d08578fb6bb9c12c7cd92ae73e289e07c360f2fdd69f9036b7baaab ;;
    tflint_linux_amd64) echo bb0a3a6043ea1bcd221fc95d49bac831bb511eb31946ca6a4050983e9e584578 ;;
    tflint_linux_arm64) echo 888de559c3716d1007496f22c949daf246c8e1f7315c320fea7eddb09de60ff2 ;;
    tflint_darwin_amd64) echo 7f2041da26ed25641bc4c844ea999a04b8cb08c67ecfd78e7281640168b6bff6 ;;
    tflint_darwin_arm64) echo 2ba8eefe6cbd5d34e5a0589a8897646e4da44c48f4c2fd9a77581d1e2b03bff8 ;;
    shellcheck_linux_x86_64) echo 6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87 ;;
    shellcheck_linux_aarch64) echo 324a7e89de8fa2aed0d0c28f3dab59cf84c6d74264022c00c22af665ed1a09bb ;;
    shellcheck_darwin_x86_64) echo ef27684f23279d112d8ad84e0823642e43f838993bbb8c0963db9b58a90464c2 ;;
    shellcheck_darwin_aarch64) echo bbd2f14826328eee7679da7221f2bc3afb011f6a928b848c80c321f6046ddf81 ;;
    *) echo "no checksum for $1" >&2; exit 1 ;;
  esac
}

fetch() { # name url
  local file
  file="$(mktemp)"
  curl -fsSL "$2" -o "$file"
  if [ "$(sha256 "$file")" != "$(expected "$1")" ]; then
    echo "checksum mismatch for $1 ($2)" >&2
    rm -f "$file"
    exit 1
  fi
  echo "$file"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if ! "$BIN/terraform" version 2>/dev/null | grep -q "v$TERRAFORM_VERSION"; then
  zip="$(fetch "terraform_${os}_${arch}" "https://releases.hashicorp.com/terraform/$TERRAFORM_VERSION/terraform_${TERRAFORM_VERSION}_${os}_${arch}.zip")"
  unzip -o -q "$zip" terraform -d "$BIN" && rm -f "$zip"
fi

if ! "$BIN/tflint" --version 2>/dev/null | grep -q "$TFLINT_VERSION"; then
  zip="$(fetch "tflint_${os}_${arch}" "https://github.com/terraform-linters/tflint/releases/download/v$TFLINT_VERSION/tflint_${os}_${arch}.zip")"
  unzip -o -q "$zip" tflint -d "$BIN" && rm -f "$zip"
fi

if ! "$BIN/shellcheck" --version 2>/dev/null | grep -q "$SHELLCHECK_VERSION"; then
  tarball="$(fetch "shellcheck_${os}_${sc_arch}" "https://github.com/koalaman/shellcheck/releases/download/v$SHELLCHECK_VERSION/shellcheck-v$SHELLCHECK_VERSION.$os.$sc_arch.tar.xz")"
  tar -xJf "$tarball" -C "$work" && mv "$work/shellcheck-v$SHELLCHECK_VERSION/shellcheck" "$BIN/" && rm -f "$tarball"
fi

# Python tools (pinned via pip). Checkov pins its own boto3, so it gets a separate venv from the Lambda tests.
for v in "$VENV" "$CHECKOV_VENV"; do
  if [ ! -x "$v/bin/python" ]; then python3 -m venv "$v"; fi
done
"$VENV/bin/pip" install --quiet --disable-pip-version-check -r "$ROOT/lambda/upload-scan/requirements-dev.txt"
"$CHECKOV_VENV/bin/pip" install --quiet --disable-pip-version-check "checkov==$CHECKOV_VERSION"

echo "tools installed in $ROOT/.tools:"
"$BIN/terraform" version | head -1
"$BIN/tflint" --version | head -1
"$BIN/shellcheck" --version | sed -n 2p
"$CHECKOV_VENV/bin/checkov" --version
