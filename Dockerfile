# Cortex — multi-stage image carrying the engine plus every scanner it drives.
#
#   docker build -t cortex:dev .
#   docker run --rm -v "$PWD":/src cortex:dev pipeline /src
#
# Scanners included: semgrep, bandit (+SARIF formatter), gosec, gitleaks,
# eslint-security, plus osv-scanner and trivy for dependency vulnerabilities.
# SpotBugs (Java) and Security Code Scan (C#) are not: both need a project build
# (mvn package / dotnet build) rather than a binary, so they belong in a
# language-specific image.

# ---------------------------------------------------------------------------
# Stage 1 — build the cortex binary
# ---------------------------------------------------------------------------
FROM golang:1.26-bookworm AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w \
            -X github.com/vektcore/cortex/internal/interfaces/cli.version=${VERSION} \
            -X github.com/vektcore/cortex/internal/interfaces/cli.commit=${COMMIT} \
            -X github.com/vektcore/cortex/internal/interfaces/cli.buildDate=${BUILD_DATE}" \
        -o /out/cortex ./cmd/cortex


# ---------------------------------------------------------------------------
# Stage 2 — gosec release binary
# ---------------------------------------------------------------------------
# Downloaded rather than compiled: building gosec from source needs more memory
# than a busy host has to spare, and the release binary is static anyway.
FROM debian:bookworm-slim AS gosec

ARG GOSEC_VERSION=2.28.0
ARG GOSEC_ARCH=amd64

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GOSEC_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin gosec \
    && /usr/local/bin/gosec --version \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Stage 3 — gitleaks and the SCA binaries from their official images
# ---------------------------------------------------------------------------
FROM zricethezav/gitleaks:latest AS gitleaks

FROM ghcr.io/google/osv-scanner:latest AS osv

FROM aquasec/trivy:latest AS trivy

# ---------------------------------------------------------------------------
# Stage 4 — runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

ARG ESLINT_VERSION=8
ARG SEMGREP_VERSION=1.174.0

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NODE_PATH=/usr/local/lib/node_modules \
    CORTEX_ESLINT_PLUGINS_DIR=/usr/local/lib/node_modules \
    CORTEX_ESLINT_FORMATTER=/usr/local/lib/node_modules/@microsoft/eslint-formatter-sarif \
    CORTEX_SEMGREP_RULES=/usr/share/cortex/rules

# git is needed for revision resolution and for "gitleaks git"; nodejs/npm for
# the ESLint adapter.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git ca-certificates nodejs npm \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        "semgrep==${SEMGREP_VERSION}" \
        bandit \
        bandit-sarif-formatter

RUN npm install -g --no-fund --no-audit \
        "eslint@${ESLINT_VERSION}" \
        eslint-plugin-security \
        @microsoft/eslint-formatter-sarif \
    && npm cache clean --force

COPY --from=builder /out/cortex /usr/local/bin/cortex
COPY --from=gosec /usr/local/bin/gosec /usr/local/bin/gosec
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Default configuration used when the scanned repository ships none, plus the
# Cortex rule pack.
COPY .cortex.docker.yaml /etc/cortex/cortex.yaml
COPY rules/ /usr/share/cortex/rules/

# /state is where the vulnerability history lives when the caller mounts it.
# /var/lib/cortex is the server's data directory: analyses, their SARIF and each
# project's tracked state. Mount it, or a redeploy forgets every project's
# history and every finding looks new again.
RUN mkdir -p /state /var/lib/cortex
VOLUME ["/state", "/var/lib/cortex"]

# `cortex serve` listens here. Nothing is exposed unless the operator maps it.
EXPOSE 8080

WORKDIR /src

# Fail fast if any scanner is missing from the image.
RUN cortex version \
    && semgrep --version \
    && bandit --version \
    && gosec --version \
    && gitleaks version \
    && eslint --version \
    && osv-scanner --version \
    && trivy --version

ENTRYPOINT ["cortex"]
CMD ["--help"]
