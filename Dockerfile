
FROM python:3.12-slim

ARG RENDER_DEMO=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/app/.cache/huggingface \
    RENDER_DEMO=${RENDER_DEMO}

WORKDIR /app

COPY requirements-docker.txt .

# Render gets only the lightweight dashboard dependencies.
# Local Docker retains its original CPU AI dependencies.
RUN if [ "$RENDER_DEMO" = "1" ]; then \
        python -m pip install \
        fastapi==0.162.0 \
        uvicorn==0.54.0 \
        Jinja2==3.1.6; \
    else \
        python -m pip install \
        --index-url https://download.pytorch.org/whl/cpu \
        torch && \
        python -m pip install \
        -r requirements-docker.txt; \
    fi

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
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT', '8000') + '/health', timeout=5)" || exit 1

CMD ["sh", "-c", \
     "exec python -m uvicorn backend.secured_app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
