# V18 server, production image (PROTOCOL.md 4c.7).
# NOT BUILT OR RUN on the build machine: Docker is not installed there.
#
# Build from the REPOSITORY ROOT (the server needs ../connectors and ../catalog):
#   docker build -f server/Dockerfile -t v18-server .
# The Anon Aadhaar circuit files are downloaded and checked against their pinned
# SHA-256 during the build (about 900 MB with the optional zkey chunks; pass
# --build-arg FETCH_CHUNKS=0 to skip the chunks).

FROM node:22.19-bookworm-slim AS build
WORKDIR /app
COPY connectors/package.json connectors/package-lock.json connectors/tsconfig.json ./connectors/
RUN cd connectors && npm ci
COPY connectors/src ./connectors/src
RUN cd connectors && npm run build && npm prune --omit=dev
COPY server/package.json server/package-lock.json ./server/
RUN cd server && npm ci
COPY server/tsconfig.json server/tsconfig.scripts.json ./server/
COPY server/src ./server/src
COPY server/scripts ./server/scripts
COPY server/migrations ./server/migrations
COPY server/assets ./server/assets
RUN cd server && npm run build
ARG FETCH_CHUNKS=1
RUN cd server && if [ "$FETCH_CHUNKS" = "1" ]; then npm run fetch-artifacts -- --chunks; else npm run fetch-artifacts; fi
RUN cd server && npm prune --omit=dev && rm -rf assets/iaca/test

FROM node:22.19-bookworm-slim
ENV NODE_ENV=production PORT=8080 V18_DATA_DIR=/data V18_CATALOG_PATH=/app/catalog/countries.json
WORKDIR /app
COPY --from=build /app/connectors ./connectors
COPY --from=build /app/server/node_modules ./server/node_modules
COPY --from=build /app/server/dist ./server/dist
COPY --from=build /app/server/migrations ./server/migrations
COPY --from=build /app/server/assets ./server/assets
COPY --from=build /app/server/package.json ./server/package.json
COPY catalog ./catalog
RUN mkdir -p /data && chown node:node /data
USER node
WORKDIR /app/server
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD node -e "fetch('http://127.0.0.1:8080/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
