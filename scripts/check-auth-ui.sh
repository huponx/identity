#!/usr/bin/env bash
# Checks that the auth-ui image the identity Dockerfile copies the sign in pages from exists (ARG AUTH_UI_IMAGE
# of build/identity/Dockerfile). A tag that was never published, or a typo, would break the image build.
# Needs docker and, for a private package, a login to ghcr.io (the workflow does it with the GITHUB_TOKEN).
set -euo pipefail
cd "$(dirname "$0")/.."

image=$(sed -n 's/^ARG AUTH_UI_IMAGE=//p' build/identity/Dockerfile | head -n 1)
if [ -z "$image" ]; then
  echo "check-auth-ui: ARG AUTH_UI_IMAGE not found in build/identity/Dockerfile" >&2
  exit 1
fi
if docker manifest inspect "$image" >/dev/null 2>&1; then
  echo "check-auth-ui: $image exists"
else
  echo "check-auth-ui: $image does not exist (or is not readable). Publish the auth-ui image from the web repository" >&2
  echo "and set ARG AUTH_UI_IMAGE in build/identity/Dockerfile to its tag." >&2
  exit 1
fi
