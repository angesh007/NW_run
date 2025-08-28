# Use a slim Python image
FROM python:3.11-slim

# System updates + minimal build deps (optional but safe)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Cloud Run provides $PORT. Your app.py already uses it.
# Ensure Flask binds 0.0.0.0 (you already do in app.py).
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Start the app
CMD ["python", "app.py"]
