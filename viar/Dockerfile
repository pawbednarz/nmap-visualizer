FROM python:3.11-slim

# Install system dependencies for OpenCV and WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    # WeasyPrint dependencies
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . /app/viar
WORKDIR /app

# Create required directories
RUN mkdir -p /tmp/viar/uploads /tmp/viar/reports /tmp/viar/frames

# Non-root user for security
RUN useradd -m -u 1000 viar && chown -R viar:viar /app /tmp/viar
USER viar

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["python", "-m", "uvicorn", "viar.main:app", "--host", "0.0.0.0", "--port", "8000"]
