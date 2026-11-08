
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/app/.cache/huggingface

WORKDIR /app

# Install CPU PyTorch from the official CPU wheel index.
RUN python -m pip install \
    --index-url https://download.pytorch.org/whl/cpu \
    torch

COPY requirements-docker.txt .

RUN python -m pip install \
    -r requirements-docker.txt

# Create an unprivileged application user.
RUN useradd --create-home --uid 10001 aegis

COPY . .

RUN mkdir -p \
    /app/logs \
    /app/results \
    /app/.cache/huggingface \
    && chown -R aegis:aegis /app

USER aegis

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s \
    --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)" || exit 1

CMD ["python", "-m", "uvicorn", \
     "backend.secured_app:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1"]
