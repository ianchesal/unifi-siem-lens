FROM node:24-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY server/package.json server/package.json
COPY web/package.json web/package.json
RUN npm ci
COPY server ./server
COPY web ./web
RUN npm run build

FROM node:24-alpine AS deps
WORKDIR /app
COPY package*.json ./
COPY server/package.json server/package.json
RUN npm ci --omit=dev --workspace=server

FROM node:24-alpine
WORKDIR /app
RUN addgroup -S lensgroup && adduser -S lensuser -G lensgroup
COPY --from=deps /app/node_modules ./node_modules
COPY server/package.json ./server/package.json
COPY --from=builder /app/server/dist ./server/dist
COPY --from=builder /app/web/dist ./web/dist
RUN mkdir -p /lens-data && chown lensuser:lensgroup /lens-data
USER lensuser
EXPOSE 3100
ENV LENS_DB_PATH=/lens-data/lens.db
# The container's network namespace is already the isolation boundary — bind
# to all interfaces here and control host exposure via how the port is
# published (`-p 3100:3100` vs. `-p 127.0.0.1:3100:3100`), the same pattern
# unifi-siem-sink and unifi-mcp-server use for their own default bind address.
ENV HOST=0.0.0.0
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3100/health || exit 1
CMD ["node", "server/dist/index.js"]
