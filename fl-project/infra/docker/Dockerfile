FROM python:3.10-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 1. Copy requirements from the src folder
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Copy all source code into /app
# This puts server.py, client.py, etc., directly in /app
COPY src/ .

# 3. Set PYTHONPATH to /app so 'import utils' works
ENV PYTHONPATH="/app"

# Default command (overridden by docker-compose)
CMD ["python", "server.py"]