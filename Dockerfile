# =============================================================================
# Stage 1 — Go binaries
#
# Builds the API and osv-scanner from source, so the final image never needs a
# Go toolchain and we never have to guess a release asset's filename.
# =============================================================================
FROM golang:1.24-bookworm AS gobuild

ARG OSV_SCANNER_VERSION=v1.9.2

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/security-api ./cmd/api
RUN CGO_ENABLED=0 GOBIN=/out go install \
      github.com/google/osv-scanner/cmd/osv-scanner@${OSV_SCANNER_VERSION}

# =============================================================================
# Stage 2 — third-party scanners
#
# Downloading here keeps wget, unzip, and the tarballs out of the final image.
# Only the extracted binaries are copied forward.
# =============================================================================
FROM debian:bookworm-slim AS fetch

ARG GITLEAKS_VERSION=8.18.1
ARG TRIVY_VERSION=0.65.0
ARG NUCLEI_VERSION=3.3.5
ARG ZAP_VERSION=2.16.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/fetch

RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ]; then GL_ARCH=linux_x64; else GL_ARCH=linux_arm64; fi; \
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GL_ARCH}.tar.gz"; \
    tar zxf "gitleaks_${GITLEAKS_VERSION}_${GL_ARCH}.tar.gz" gitleaks; \
    install -D -m 0755 gitleaks /out/gitleaks

RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ]; then TR_ARCH=Linux-64bit; else TR_ARCH=Linux-ARM64; fi; \
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TR_ARCH}.tar.gz"; \
    tar zxf "trivy_${TRIVY_VERSION}_${TR_ARCH}.tar.gz" trivy; \
    install -D -m 0755 trivy /out/trivy

RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ]; then NU_ARCH=linux_amd64; else NU_ARCH=linux_arm64; fi; \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NU_ARCH}.zip"; \
    unzip -q "nuclei_${NUCLEI_VERSION}_${NU_ARCH}.zip" nuclei; \
    install -D -m 0755 nuclei /out/nuclei

# ZAP ships as a directory, not a single binary.
RUN set -eux; \
    wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"; \
    mkdir -p /opt; \
    tar xzf "ZAP_${ZAP_VERSION}_Linux.tar.gz" -C /opt

# =============================================================================
# Stage 3 — runtime
#
# JRE rather than JDK: ZAP only needs to run Java, not compile it. Python is
# here solely because semgrep is distributed as a Python package.
# =============================================================================
FROM eclipse-temurin:17-jre-jammy

ARG ZAP_VERSION=2.16.1
ARG SEMGREP_VERSION=1.86.0

ENV ZAP_HOME=/opt/ZAP_${ZAP_VERSION} \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# git is required by gitleaks to walk history. Everything else is dropped.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates git python3 python3-pip \
    && pip3 install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/*

COPY --from=gobuild /out/security-api /app/security-api
COPY --from=gobuild /out/osv-scanner  /usr/local/bin/osv-scanner
COPY --from=fetch   /out/gitleaks     /usr/local/bin/gitleaks
COPY --from=fetch   /out/trivy        /usr/local/bin/trivy
COPY --from=fetch   /out/nuclei       /usr/local/bin/nuclei
COPY --from=fetch   /opt/ZAP_${ZAP_VERSION} /opt/ZAP_${ZAP_VERSION}

# ZAP wrapper. Heap is capped so a scan cannot take the container down.
RUN printf '%s\n' \
      '#!/bin/sh' \
      'cd /zap/wrk' \
      'exec java -Xmx512m -Djava.io.tmpdir=/zap/tmp/ -jar '"${ZAP_HOME}/zap-${ZAP_VERSION}.jar"' "$@"' \
      > /usr/local/bin/zap.sh \
    && chmod 0755 /usr/local/bin/zap.sh

RUN useradd -m appuser \
    && mkdir -p /zap/wrk /zap/tmp /app/temp /app/workspace \
    && chown -R appuser:appuser /zap /app "${ZAP_HOME}"

USER appuser

# Templates live in the user's home, so fetch them as the user that reads them.
RUN nuclei -update-templates -silent || true

WORKDIR /app
EXPOSE 5000
ENTRYPOINT ["./security-api"]
