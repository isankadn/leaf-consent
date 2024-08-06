# Dockerfile
FROM python:3.9-slim-buster

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 5000

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc sqlite3 libsqlite3-dev

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy project
COPY . /app/

# Create a directory for the SQLite database
RUN mkdir -p /app/instance && chown -R 1000:1000 /app/instance

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' --uid 1000 appuser
USER appuser

# Default command for development
CMD ["flask", "run", "--host=0.0.0.0", "--reload"]
