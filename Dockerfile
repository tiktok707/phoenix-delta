FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    bluez \
    bluez-tools \
    sqlite3 \
    iputils-ping \
    net-tools \
    wireless-tools \
    iw \
    aircrack-ng \
    && rm -rf /var/lib/apt/lists/*

# Rust for Bluetooth Conqueror
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install btleplug 2>/dev/null || true

# Go for Embedded Implant cross-compilation
RUN wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY c2_server/ /app/c2_server/
COPY layers/ /app/layers/
COPY ai_fuzzer/ /app/ai_fuzzer/
COPY tools/ /app/tools/
COPY implant/ /app/implant/
COPY bluetooth_conqueror/ /app/bluetooth_conqueror/
COPY payloads/ /app/payloads/
COPY configs/ /app/configs/
COPY db/ /app/db/

# Create certs directory
RUN mkdir -p /app/certs

# Expose C2 ports
EXPOSE 443 4444

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('https://localhost:443/api/status')" || exit 1

# Start C2 Server
CMD ["python3", "-m", "c2_server.c2_master"]
