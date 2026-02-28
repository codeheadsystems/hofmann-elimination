# ──────────────────────────────────────────────────────────────────────────────
# Stage 1 – Build the demo UI
# ──────────────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /build

# Copy the TypeScript client source
COPY hofmann-typescript/ ./

# Install dependencies and build the demo bundle
RUN npm ci && npm run build:demo

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2 – Serve with nginx
# ──────────────────────────────────────────────────────────────────────────────
FROM nginx:alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Install the demo-specific nginx config
COPY hofmann-demo/demo-ui/nginx.conf /etc/nginx/conf.d/hofmann-demo.conf

# Copy built static files
COPY --from=builder /build/dist-demo/ /usr/share/nginx/html/

EXPOSE 80
