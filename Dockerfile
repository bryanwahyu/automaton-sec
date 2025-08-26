FROM golang:1.24-bullseye AS builder

# build Go app
WORKDIR /app
COPY . .
RUN go build -o security-api ./cmd/api

# final image
FROM debian:bullseye-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget curl unzip python3 python3-pip git \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo deb https://aquasecurity.github.io/trivy-repo/deb stable main > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y trivy

# Install Gitleaks
RUN wget https://github.com/zricethezav/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    && tar -xvf gitleaks_8.18.4_linux_x64.tar.gz -C /usr/local/bin gitleaks \
    && rm gitleaks_8.18.4_linux_x64.tar.gz

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip \
    && unzip nuclei_3.3.5_linux_amd64.zip -d /usr/local/bin \
    && rm nuclei_3.3.5_linux_amd64.zip

# Install ZAP (baseline scan)
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz \
    && tar -xvf ZAP_2.14.0_Linux.tar.gz -C /opt \
    && ln -s /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zap.sh \
    && ln -s /opt/ZAP_2.14.0/zap-baseline.py /usr/local/bin/zap-baseline.py \
    && rm ZAP_2.14.0_Linux.tar.gz

# Add nuclei templates
RUN nuclei -update-templates

# Add non-root user
RUN useradd -m appuser
USER appuser

WORKDIR /app
COPY --from=builder /app/security-api /app/security-api

ENTRYPOINT ["./security-api"]
EXPOSE 8000
