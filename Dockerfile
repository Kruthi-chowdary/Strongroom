# syntax=docker/dockerfile:1

# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /app

COPY package*.json ./
# Install all deps (including devDeps needed for tsc)
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM node:20-slim AS runtime

# Run as non-root user (security hardening)
RUN groupadd --gid 1001 strongroom \
 && useradd  --uid 1001 --gid strongroom --no-create-home strongroom

WORKDIR /app

# Copy only production dependencies manifest, then install prod deps only
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy compiled output from builder
COPY --from=builder /app/dist ./dist

# Copy schema so db.ts can read it at runtime (__dirname will be dist/)
COPY src/schema.sql ./dist/schema.sql

# Create the storage directory outside the web root; owned by the app user.
# Actual file encryption is handled at the application layer (Rule 6).
RUN mkdir -p /data/storage && chown strongroom:strongroom /data/storage

USER strongroom

# PORT is provided at runtime via env (see .env.example)
ENV NODE_ENV=production
EXPOSE ${PORT:-3000}

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT||3000) + '/health', r => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "dist/server.js"]
