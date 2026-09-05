# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY . .

# Create directory for uploads and db
RUN mkdir -p uploads/profile_images

EXPOSE 5000

ENV VGUARD_ENV=production
ENV FLASK_APP=wsgi.py

# Initialize database, seed data, and run gunicorn
CMD ["sh", "-c", "python manage.py init-db && python manage.py seed && gunicorn --bind 0.0.0.0:5000 wsgi:app"]
