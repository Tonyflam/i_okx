#!/bin/sh
set -eu

mkdir -p /data

# One-time state seeding: SEED_STATE_B64_1..N hold a base64 tar.gz of
# .onchainos (wallet session) + .okx-agent-task (XMTP identity), split into
# <32KB chunks (Railway env-var size limit). Applied only when the volume is
# empty, so later state changes persist.
if [ ! -f /data/.onchainos/session.json ]; then
  seed=""
  i=1
  while :; do
    chunk=$(printenv "SEED_STATE_B64_${i}" 2>/dev/null || true)
    [ -n "$chunk" ] || break
    seed="${seed}${chunk}"
    i=$((i + 1))
  done
  if [ -n "$seed" ]; then
    echo "[entrypoint] seeding identity state from $((i - 1)) SEED_STATE_B64_* chunk(s)"
    printf '%s' "$seed" | base64 -d | tar -xz -C /data
  fi
fi

# Wait for identity state to be seeded before starting the daemon.
# Seeding: tar of ~/.onchainos + ~/.okx-agent-task extracted into /data.
while [ ! -f /data/.onchainos/session.json ]; do
  echo "[entrypoint] waiting for identity state in /data (.onchainos/session.json missing)..."
  sleep 15
done

echo "[entrypoint] identity state present; starting okx-a2a daemon in foreground"
# This container is the only daemon for this volume; clear stale locks from prior boots.
rm -rf /data/.okx-agent-task/run/daemon.lock /data/.okx-agent-task/run/listener.pid /data/.okx-agent-task/run/user-attention.sock
exec okx-a2a run
