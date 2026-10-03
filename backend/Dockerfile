FROM zricethezav/gitleaks:v8.24.3 AS gitleaks
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.121.0 "setuptools<81"
ENV PATH="/opt/semgrep/bin:${PATH}"
COPY app ./app
COPY rules ./rules
RUN useradd --uid 10001 --create-home scanner && chown -R scanner:scanner /srv
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/usr/local/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
