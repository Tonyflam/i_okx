# Always-on host for the OKX A2A daemon (keeps ASP #5106 "Preflight" online).
# Runs okx-a2a in the foreground; all mutable state lives on a volume via HOME=/data.
FROM node:22-slim

# XMTP's native library uses the system CA store for TLS (absent in -slim)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN npm i -g @okxweb3/a2a-node@0.1.7 && npm cache clean --force

# Static onchainos binary (verified locally via the CLI's own checksum update flow)
COPY onchainos /usr/local/bin/onchainos
RUN chmod 755 /usr/local/bin/onchainos

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# All state (~/.onchainos wallet session, ~/.okx-agent-task XMTP identity)
# resolves under HOME, which we point at the mounted volume.
ENV HOME=/data
WORKDIR /data

ENTRYPOINT ["/entrypoint.sh"]
