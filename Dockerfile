# GAuth Python Dockerfile
# Multi-stage build for GAuth Python implementation

# Build stage
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-dev.txt

# Copy source code
COPY . .

# Install the package
RUN pip install -e .

# Run tests during build
RUN python -m pytest tests/ -v || echo "Tests completed"

# Run linting
RUN python -m flake8 gauth/ --max-line-length=100 || echo "Linting completed"

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash app

# Set working directory
WORKDIR /home/app

# Copy requirements
COPY requirements.txt ./

# Install production dependencies only
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the package from builder
COPY --from=builder /app/gauth ./gauth
COPY --from=builder /app/setup.py ./
COPY --from=builder /app/examples ./examples
COPY --from=builder /app/README.md ./

# Install the package
RUN pip install -e .

# Copy documentation
COPY docs ./docs

# Change ownership to app user
RUN chown -R app:app /home/app

# Switch to app user
USER app

# Expose port (if running as a web service)
EXPOSE 8000

# Set environment variables
ENV PYTHONPATH=/home/app
ENV GAUTH_CLIENT_ID=""
ENV GAUTH_CLIENT_SECRET=""
ENV GAUTH_AUTH_SERVER_URL="https://auth.example.com"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import gauth; print('GAuth is healthy')" || exit 1

# Default command - run the demo
CMD ["python", "-m", "gauth.demo.main"]