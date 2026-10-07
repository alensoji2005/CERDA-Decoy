FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
# CPU-only torch keeps the image small; the decoy never needs a GPU.
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt

COPY src ./src
COPY decoy_server.py cerf_engine.py dashboard.py ./

# Telemetry, sessions and blocklists live on the shared /data volume.
ENV PYTHONPATH=/app
WORKDIR /data
RUN useradd --system --uid 10001 cerda && chown cerda /data
USER cerda

EXPOSE 2222 8080 8501
CMD ["python", "/app/decoy_server.py"]
