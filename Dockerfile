FROM alpine:3.20 AS builder

WORKDIR /build

RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-wheel \
    gcc \
    musl-dev \
    libffi-dev

COPY requirements.txt ./

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip "setuptools>=78.1.1" wheel && \
    grep -v -i -E "^opencv" requirements.txt > /tmp/requirements-pip.txt || true && \
    if [ -s /tmp/requirements-pip.txt ]; then \
        /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements-pip.txt; \
    fi && \
    /opt/venv/bin/pip uninstall -y setuptools wheel pip

FROM alpine:3.20 AS runner

LABEL org.opencontainers.image.title="RTSP Scanner Service" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
    python3 \
    py3-opencv \
    ca-certificates \
    tzdata \
    dumb-init && \
    rm -rf /var/cache/apk/* /tmp/*

ARG UID=10001
ARG GID=10001
RUN addgroup -g ${GID} appgroup && \
    adduser -u ${UID} -G appgroup -s /sbin/nologin -D -h /app appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/opt/venv/lib/python3.12/site-packages:/usr/lib/python3.12/site-packages" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STORAGE_DIR="/var/www/html/scan"

RUN mkdir -p /var/www/html/scan /app/storage && \
    chown -R appuser:appgroup /var/www/html/scan /app

COPY --chown=appuser:appgroup 41_scan_stream_default.py ./
COPY --chown=appuser:appgroup vulnerable_examples.py ./

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import cv2, requests, pymysql; exit(0)" || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["python3", "41_scan_stream_default.py"]
