# npryx-scan: deploy anywhere (Fly, Railway, a VPS, Kubernetes, Cloud Run…).
#
#   docker build -t npryx-scan .
#   docker run -p 8787:8787 -v npryx-scan-data:/data npryx-scan
#
# Static scanning needs nothing else. For sandbox (deep) scans, build with
# --build-arg WITH_DOCKER_CLI=1, set NPRYX_SCAN_SANDBOX=docker, and give the
# container a Docker daemon (e.g. -v /var/run/docker.sock:/var/run/docker.sock).
# Only do that on a host dedicated to scanning: the socket is root-equivalent.

FROM rust:1-bookworm AS build
WORKDIR /src
# Cache dependency builds separately from our sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked 2>/dev/null || true
COPY src ./src
COPY sandbox ./sandbox
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM debian:bookworm-slim
ARG WITH_DOCKER_CLI=0
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && if [ "$WITH_DOCKER_CLI" = "1" ]; then apt-get install -y --no-install-recommends docker.io; fi \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /data --uid 10001 scan \
    && mkdir -p /data && chown scan /data
COPY --from=build /src/target/release/npryx-scan /usr/local/bin/npryx-scan
USER scan
WORKDIR /data
ENV NPRYX_SCAN_BIND=0.0.0.0:8787 \
    NPRYX_SCAN_CACHE_DIR=/data/cache \
    NPRYX_SCAN_SIGNING_KEY=/data/signing.key
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8787 && printf 'GET /healthz HTTP/1.0\\r\\n\\r\\n' >&3 && grep -q ok <&3"]
ENTRYPOINT ["npryx-scan"]
