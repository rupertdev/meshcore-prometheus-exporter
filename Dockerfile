FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir "meshcore-cli" \
    && pip install --no-cache-dir .

RUN useradd --system --uid 10001 --create-home exporter \
    && mkdir -p /data \
    && chown -R exporter:exporter /data /app

USER exporter

VOLUME ["/data"]
EXPOSE 9108

ENTRYPOINT ["meshcore-prom-exporter"]
CMD ["--db-path", "/data/telemetry.db", "--listen-address", "0.0.0.0", "--listen-port", "9108"]
