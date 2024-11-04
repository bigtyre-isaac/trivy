# Use Python image
FROM python:3.9-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    rm -rf /var/lib/apt/lists/*

# Install Trivy from GitHub release (using the correct latest version)
RUN wget -O /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v0.57.0/trivy_0.57.0_Linux-64bit.tar.gz && \
    tar zxvf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz

# Install Flask and Gunicorn
RUN pip install Flask gunicorn

# Copy app code
COPY trivy_api.py /app/trivy_api.py
WORKDIR /app

# Run the app with Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "trivy_api:app"]
