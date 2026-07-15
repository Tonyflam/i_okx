FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[payments]'

RUN useradd --create-home appuser
USER appuser

ENV PREFLIGHT_DB_PATH=/home/appuser/preflight.db
EXPOSE 8000

# Shell form so Railway's injected $PORT is honored; proxy flags so client IPs
# and scheme survive the platform edge (rate limiting keys on real client IP).
CMD uvicorn preflight.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips '*'
