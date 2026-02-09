# Dockerfile for YARA LLM Generator
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies for YARA and analysis tools
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/malware_samples data/benign_samples data/generated_rules

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose port if needed (for future API/web interface) (Don't think we will get this far tho LOL)
EXPOSE 8000

# Default command (will be overridden by docker-compose or start.sh)
CMD ["python", "-m", "src.main"]
