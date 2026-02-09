FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY tsconfig.json tsup.config.ts ./
COPY src/ src/
RUN npm run build

# --- Production image ---
FROM node:20-alpine

RUN addgroup -g 1001 agentci && \
    adduser -u 1001 -G agentci -s /bin/sh -D agentci

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --from=builder /app/dist dist/
COPY LICENSE README.md ./

RUN mkdir -p /data/.agentci && chown -R agentci:agentci /data

USER agentci

ENV NODE_ENV=production
EXPOSE 8788
VOLUME ["/data"]

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8788/healthz',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

ENTRYPOINT ["node", "dist/cli/main.js"]
CMD ["dashboard", "--dir", "/data/.agentci/runs", "--port", "8788"]
