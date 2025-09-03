# ========================
# Build Stage
# ========================
FROM golang:1.24-bullseye AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o security-api ./cmd/api

# ========================
# Final Stage (FAT Image)
# ========================
FROM openjdk:17-jdk-slim-bullseye
# Install dependencies
RUN apt-get update --fix-missing \
    && apt-get install -y wget curl unzip git python3 python3-pip \
    && pip3 install --no-cache-dir pyyaml requests \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
#==== install Gitleaks (arch-aware) ====
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ]; then GL_ARCH=linux_x64; else GL_ARCH=linux_arm64; fi; \
    wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_${GL_ARCH}.tar.gz; \
    tar zxf gitleaks_8.18.1_${GL_ARCH}.tar.gz; \
    mv gitleaks /usr/local/bin/; \
    chmod +x /usr/local/bin/gitleaks; \
    rm gitleaks_8.18.1_${GL_ARCH}.tar.gz; \
    gitleaks version
    
#==== install Trivy CLI (arch-aware) ====
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ]; then TR_ARCH=Linux-64bit; else TR_ARCH=Linux-ARM64; fi; \
    wget -q https://github.com/aquasecurity/trivy/releases/download/v0.65.0/trivy_0.65.0_${TR_ARCH}.tar.gz; \
    tar zxf trivy_0.65.0_${TR_ARCH}.tar.gz; \
    mv trivy /usr/local/bin/; \
    chmod +x /usr/local/bin/trivy; \
    rm trivy_0.65.0_${TR_ARCH}.tar.gz; \
    trivy --version

# === Install Nuclei (arch-aware) ===
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ]; then NU_ARCH=linux_amd64; else NU_ARCH=linux_arm64; fi; \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_${NU_ARCH}.zip; \
    unzip -q nuclei_3.3.5_${NU_ARCH}.zip -d /usr/local/bin; \
    rm nuclei_3.3.5_${NU_ARCH}.zip; \
    chmod +x /usr/local/bin/nuclei; \
    nuclei -update-templates

# === Install ZAP (Simple Approach) ===
# Download ZAP JAR
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz \
    && tar -xzf ZAP_2.16.1_Linux.tar.gz -C /opt \
    && rm ZAP_2.16.1_Linux.tar.gz

# Create simple ZAP wrapper scripts
RUN echo '#!/bin/bash' > /usr/local/bin/zap.sh \
    && echo 'cd /opt/ZAP_2.16.1' >> /usr/local/bin/zap.sh \
    && echo 'java -jar zap-2.16.1.jar "$@"' >> /usr/local/bin/zap.sh \
    && chmod +x /usr/local/bin/zap.sh

# Download and setup ZAP baseline script
RUN wget -O /usr/local/bin/zap-baseline.py \
    https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap-baseline.py \
    && chmod +x /usr/local/bin/zap-baseline.py \
    && sed -i '1i#!/usr/bin/env python3' /usr/local/bin/zap-baseline.py

# Test ZAP installation
RUN echo "=== ZAP INSTALLATION TEST ===" \
    && ls -la /opt/ZAP_2.16.1/ \
    && echo "ZAP JAR exists:" \
    && ls -la /opt/ZAP_2.16.1/zap-2.16.1.jar \
    && echo "ZAP script exists:" \
    && ls -la /usr/local/bin/zap.sh \
    && echo "ZAP baseline script exists:" \
    && ls -la /usr/local/bin/zap-baseline.py \
    && echo "Testing Java:" \
    && java -version \
    && echo "Testing ZAP help (quick test):" \
    && timeout 5 zap.sh -help || echo "ZAP help test completed" \
    && echo "=== ZAP TEST COMPLETED ==="

# Create user and set ownership
RUN useradd -m appuser \
    && mkdir -p /home/appuser/.ZAP \
    && chown -R appuser:appuser /opt/ZAP_2.16.1 /home/appuser/.ZAP

# Copy and setup application
WORKDIR /app
COPY --from=builder /app/security-api /app/security-api

# Set proper permissions
RUN chmod +x /app/security-api && chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["./security-api"]
EXPOSE 8000