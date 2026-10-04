FROM python:3.12-slim
WORKDIR /srv
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock && playwright install --with-deps chromium
RUN useradd --uid 10001 --create-home scanner && mkdir /run/asd-browser && chown scanner:scanner /run/asd-browser && cp -a /root/.cache/ms-playwright /opt/browsers && chmod -R a+rX /opt/browsers
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/browsers PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY server.py .
USER 10001:10001
CMD ["python", "server.py"]
