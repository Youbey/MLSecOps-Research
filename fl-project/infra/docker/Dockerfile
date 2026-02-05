# Use Python 3.10 slim image
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY fl-project/src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY fl-project/src/ .

ENV PYTHONPATH="${PYTHONPATH}:/src"

# Default to server
CMD ["python", "server.py"]