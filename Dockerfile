# Build stage
FROM python:3.12-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libcups2-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY build/requirements.txt /tmp/requirements.txt
RUN pip3 install --user --no-cache-dir -r /tmp/requirements.txt

# Runtime stage
FROM python:3.12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcups2 \
    usbutils \
    util-linux \
    udev \
    bash \
    curl \
    micro \
    openssl \
    python3-tk \
    libgtk2.0-dev \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local

WORKDIR /vault