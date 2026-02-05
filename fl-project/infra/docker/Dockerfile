# Use Python 3.10 slim image
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from the src directory
COPY fl-project/src/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY fl-project/src/ ./src/

# Set Python path to include the src directory
ENV PYTHONPATH="${PYTHONPATH}:/app/src"

# Default to server
CMD ["python", "src/server.py"]