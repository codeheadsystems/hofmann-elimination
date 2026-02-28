# ──────────────────────────────────────────────────────────────────────────────
# Stage 1 – Build
# ──────────────────────────────────────────────────────────────────────────────
FROM gradle:8.12-jdk21 AS builder

WORKDIR /build

# Initialise a minimal git repository so that settings.gradle.kts can run
# "git describe --tags --exact-match HEAD" without failing.  The project
# version will fall back to the gradle.properties default (0.x-SNAPSHOT).
RUN git init && \
    git config user.email "docker@build" && \
    git config user.name "Docker Build"

# Copy the full project source (.dockerignore excludes generated build/ dirs)
COPY . .

# Build the installable distribution, skipping tests for a faster image build
RUN ./gradlew :hofmann-testserver:installDist --no-daemon -x test

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2 – Runtime
# ──────────────────────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Copy the application distribution produced by installDist:
#   bin/hofmann-testserver  – start script
#   lib/*.jar               – application and dependency JARs
COPY --from=builder /build/hofmann-testserver/build/install/hofmann-testserver/ ./

# Embed the demo configuration.
# Override individual keys via environment variables (see docker-compose.yml),
# or replace the entire file with a volume mount:
#   -v ./my-config.yml:/config/config.yml
COPY --from=builder /build/hofmann-demo/server/config.yml /config/config.yml

# Application port / Admin port (health check, metrics)
EXPOSE 8080 8081

ENTRYPOINT ["bin/hofmann-testserver", "server", "/config/config.yml"]
