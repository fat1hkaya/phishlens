FROM python:3.12-slim

LABEL org.opencontainers.image.title="PhishLens" \
      org.opencontainers.image.description="Phishing e-mail analyzer for SOC triage" \
      org.opencontainers.image.source="https://github.com/fat1hkaya/phishlens"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PHISHLENS_HOST=0.0.0.0 PHISHLENS_PORT=5000 PHISHLENS_SAMPLES=/app/samples

WORKDIR /app
COPY pyproject.toml README.md ./
COPY phishlens ./phishlens
COPY samples ./samples
RUN pip install --no-cache-dir . gunicorn \
 && useradd --create-home --uid 10001 phishlens
USER phishlens

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz')"
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "phishlens.web.app:create_app()"]
