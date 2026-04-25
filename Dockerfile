FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:/root/.local/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "uv>=0.8,<1.0"

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY fixtures ./fixtures
COPY resources ./resources
COPY docker/entrypoint.sh /entrypoint.sh

RUN uv sync --frozen --no-dev

RUN groupadd --system honeypot \
    && useradd --system --gid honeypot --create-home --home-dir /home/honeypot honeypot \
    && mkdir -p /app/tmp /app/logs /app/pcap \
    && chown -R honeypot:honeypot /app /home/honeypot \
    && chmod 755 /entrypoint.sh

EXPOSE 1502 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "honeypot.main"]
