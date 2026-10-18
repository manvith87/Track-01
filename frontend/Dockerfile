# BlastRadius frontend image: build the SPA with Node, serve it with nginx and
# reverse-proxy /api and /health to the backend service (same origin, no CORS).
#
# Build (from the frontend/ directory):  docker build -t blastradius-frontend .

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
