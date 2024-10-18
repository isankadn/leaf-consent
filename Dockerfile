# Dockerfile
FROM python:3.9-slim-buster

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP app.py

RUN apt-get update && apt-get install -y --no-install-recommends gcc sqlite3 libsqlite3-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . /app/

RUN mkdir -p /app/instance && chown -R 1000:1000 /app/instance

RUN adduser --disabled-password --gecos '' --uid 1000 appuser
USER appuser

# Default command for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]


