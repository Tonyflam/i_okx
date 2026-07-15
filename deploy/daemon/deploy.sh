#!/usr/bin/env bash
# Deploy the always-on OKX A2A daemon to Railway (service: preflight-daemon).
#
# Stages the build context OUTSIDE the git repo: `railway up` honors .gitignore,
# which excludes the local onchainos binary from uploads — staging avoids that
# without committing a 12 MB binary.
#
# Prereqs: railway CLI linked to the "preflight" project; onchainos installed locally.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# Private deploy settings (git-ignored): RAILWAY_PROJECT_ID=<your project id>
[ -f "$here/.env.local" ] && . "$here/.env.local"
: "${RAILWAY_PROJECT_ID:?Set RAILWAY_PROJECT_ID (Railway project to link, or put it in deploy/daemon/.env.local)}"
stage="$(mktemp -d /tmp/preflight-daemon-ctx.XXXXXX)"
trap 'rm -rf "$stage"' EXIT

cp "$here/Dockerfile" "$here/entrypoint.sh" "$here/railway.json" "$stage/"
cp "$(command -v onchainos)" "$stage/onchainos"

(cd "$stage" \
  && railway link -p "$RAILWAY_PROJECT_ID" -e production -s preflight-daemon >/dev/null \
  && railway up --ci)
