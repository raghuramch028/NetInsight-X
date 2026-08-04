# Use official slim Python runtime
FROM python:3.10-slim

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /code

# Install system dependencies needed for PostgreSQL, compilation, and pcap
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project code to the container
COPY . /code/

# Set environment variables for django settings
ENV DJANGO_SETTINGS_MODULE=netinsight.config.settings
ENV PORT=7860

# Collect static files
RUN python manage.py collectstatic --noinput

# Expose Hugging Face default container port
EXPOSE 7860

# Run migrations and start gunicorn server (using optimized 1 worker, 2 threads configuration)
CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn netinsight.wsgi:application --bind 0.0.0.0:7860 --workers 1 --threads 2 --timeout 120"]
