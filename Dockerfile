# syntax=docker/dockerfile:1

# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM node:22-slim AS builder
WORKDIR /app
# Toolchain in case better-sqlite3 has to compile from source.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM node:22-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1001 strongroom \
 && useradd --uid 1001 --gid strongroom --no-create-home strongroom
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
# dist already contains schema.sql (copied by the build script)
COPY --from=builder /app/dist ./dist

# Writable data dir for the SQLite file and (later) encrypted uploads.
RUN mkdir -p /data/storage && chown -R strongroom:strongroom /data
ENV NODE_ENV=production
ENV DB_PATH=/data/strongroom.db
ENV STORAGE_DIR=/data/storage
USER strongroom
EXPOSE 3000
CMD ["node", "dist/server.js"]