# syntax=docker/dockerfile:1

# ---- build stage ----
FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && \
    cp target/release/chadlands-validator /usr/local/bin/chadlands-validator

# ---- runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*

ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd --gid $APP_GID appuser && \
    useradd --uid $APP_UID --gid $APP_GID --no-log-init --create-home appuser

COPY --from=builder /usr/local/bin/chadlands-validator /usr/local/bin/chadlands-validator

USER 1000:1000
WORKDIR /vault

ENTRYPOINT ["chadlands-validator"]
CMD ["check", "--vault", "."]
