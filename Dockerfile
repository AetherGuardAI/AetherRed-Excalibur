FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ src/
COPY campaigns/ campaigns/

RUN pip install --no-cache-dir ".[full]"

# Run as non-root user
RUN useradd --create-home --shell /bin/bash aetherguard && \
    chown -R aetherguard:aetherguard /app
USER aetherguard

EXPOSE 8100

ENTRYPOINT ["excalibur"]
CMD ["--help"]
