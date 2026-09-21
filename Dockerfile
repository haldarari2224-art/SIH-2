# Multi-stage Dockerfile for IPsec Sentinel (Works on Hugging Face Spaces, Render, Railway, Docker)
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy backend dependencies and install
COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code including bundled dist
COPY backend/ /app/backend/

WORKDIR /app/backend

ENV PORT=7860
EXPOSE 7860

CMD ["python", "main.py"]
