# V18 demo site ("Reserve Cellar"), PRODUCTION mode: no test wallet and no developer tools.
#
# Build from the sdk-web/ folder (the demo site needs ../verify-node and ../widget):
#   docker build -f demo-site/Dockerfile -t v18-demo-site .
# Run (put a TLS proxy in front; SITE_ORIGIN is the https address visitors use):
#   docker run -p 3000:3000 -e V18_SERVER=https://api.v18.example -e SITE_ORIGIN=https://shop.example -e TRUST_PROXY=1 v18-demo-site
#
# Not run here: Docker is not installed on the build machine (see docs/web/DEPLOY-DEMO.md).

# ---- build: compile @v18/verify, the widget bundle and the demo site ---------------------------
FROM node:22-alpine AS build
WORKDIR /src

COPY verify-node/package.json verify-node/package-lock.json verify-node/
RUN npm ci --prefix verify-node --no-audit --no-fund
COPY widget/package.json widget/package-lock.json widget/
RUN npm ci --prefix widget --no-audit --no-fund
COPY demo-site/package.json demo-site/package-lock.json demo-site/
RUN npm ci --prefix demo-site --no-audit --no-fund

COPY verify-node/ verify-node/
COPY widget/ widget/
COPY demo-site/ demo-site/
RUN npm run build --prefix verify-node \
 && npm run build --prefix widget \
 && npm run build --prefix demo-site

# The versioned widget the page loads (its SRI hash is worked out when the site starts).
RUN mkdir -p release \
 && cp widget/dist/v18.min.js "release/v18-$(node -p "require('./widget/package.json').version").min.js"
# Dev-only and test-only code stays out of the image.
RUN rm -rf verify-node/dist/tests \
 demo-site/dist/tests demo-site/dist/mock-v18 demo-site/dist/wallet-test demo-site/dist/client demo-site/dist/public

# ---- run ----------------------------------------------------------------------------------------
FROM node:22-alpine
ENV NODE_ENV=production DEMO_MODE=production PORT=3000
WORKDIR /app

COPY --from=build /src/verify-node/package.json verify-node/package.json
COPY --from=build /src/verify-node/dist verify-node/dist
COPY --from=build /src/widget/package.json widget/package.json
COPY --from=build /src/release release
COPY --from=build /src/demo-site/package.json /src/demo-site/package-lock.json demo-site/
RUN npm ci --prefix demo-site --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /src/demo-site/dist demo-site/dist
COPY --from=build /src/demo-site/public demo-site/public

USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "demo-site/dist/server.js"]
