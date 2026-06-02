FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    ca-certificates \
    gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system honeypot \
    && useradd --system --gid honeypot --home-dir /app --shell /usr/sbin/nologin honeypot

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=honeypot:honeypot . .
RUN touch honeypot.db honeypot.log honeypot_out.log \
    && chown honeypot:honeypot honeypot.db honeypot.log honeypot_out.log \
    && chmod +x /app/docker-entrypoint.sh

EXPOSE 2222 2121 8080 2323 4444 5050

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/api/health', timeout=3)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python", "main.py"]
