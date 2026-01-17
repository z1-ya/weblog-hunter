FROM python:3.11-slim

LABEL maintainer="z1-ya"
LABEL description="weblog-hunter - Automated web log reconnaissance and threat hunting tool"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY weblog_hunter/ weblog_hunter/
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

# Install the package
RUN pip install --no-cache-dir .

# Create directories for logs and reports
RUN mkdir -p /logs /reports

# Set working directory for easier volume mounting
WORKDIR /work

ENTRYPOINT ["weblog-hunter"]
CMD ["--help"]
