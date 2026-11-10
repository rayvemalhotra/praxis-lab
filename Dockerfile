FROM python:3.12-slim
# the site runs as an ordinary user, not as root
RUN useradd --create-home --uid 10001 threatprint
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# .dockerignore keeps the password files, the virtual environment, caches, logs and contributed fingerprints out of the image
COPY --chown=threatprint:threatprint . .
USER threatprint
EXPOSE 7860
ENV STREAMLIT_SERVER_HEADLESS=true STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7860/_stcore/health', timeout=4).status == 200 else 1)"
CMD ["streamlit", "run", "app.py", "--server.port", "7860", "--server.address", "0.0.0.0"]
