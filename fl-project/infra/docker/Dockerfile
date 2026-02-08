FROM python:3.10-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 1. Copy requirements from the src folder
COPY src/requirements.txt .
# Copy requirements from the src directory
COPY fl-project/src/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 2. Copy all source code into /app
# This puts server.py, client.py, etc., directly in /app
COPY src/ .
# Copy application code
COPY fl-project/src/ ./src/

# 3. Set PYTHONPATH to /app so 'import utils' works
ENV PYTHONPATH="/app"
# Set Python path to include the src directory
ENV PYTHONPATH="${PYTHONPATH}:/app/src"

# Default to server
CMD ["python", "src/server.py"]