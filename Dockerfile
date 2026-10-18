# BlastRadius backend image.
#
# Build:  docker build -t blastradius-backend .
# Run:    docker run --rm -p 8000:8000 \
#           -e BLASTRADIUS_GRAPH_HOST=host.docker.internal \
#           blastradius-backend
#
# The image contains only the FastAPI backend.  The FalkorDB graph and the
# frontend are separate services (see docker-compose.yml).

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# `git` is required by the default (auto) retrieval strategy; the archive
# fallback works without it but the git path is the documented default.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/blastradius

RUN useradd --create-home --uid 10001 blastradius

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# The Phase 6 action store defaults to the platform temp directory; in a
# container always mount a durable volume here (see docker-compose.yml).
RUN mkdir -p /var/lib/blastradius && chown blastradius:blastradius /var/lib/blastradius
ENV BLASTRADIUS_ACTIONS_STORE_PATH=/var/lib/blastradius/actions.sqlite

USER blastradius

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
