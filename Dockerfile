# ============================================================
# Ai-SOC.MSP Dashboard V2 — Docker Image
# FortiSIEM-style interface on port 8444
# ============================================================
FROM python:3.11-slim

LABEL maintainer="Ai-SOC.MSP Team"
LABEL description="FortiSIEM-style SOC Dashboard for Wazuh"
LABEL version="2.0"

# Install openssl for self-signed cert generation
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl curl && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Create directories for certs and data
RUN mkdir -p /app/certs /app/data

# Expose port
EXPOSE 8444

# Health check — hit login page
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsk https://127.0.0.1:8444/login || exit 1

# Run the app
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8444", "--host", "0.0.0.0"]
