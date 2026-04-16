FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/root/go/bin:/usr/local/bin:$PATH"

# Install system deps in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git && \
    rm -rf /var/lib/apt/lists/*

# Install osv-scanner via prebuilt binary (avoids ~500MB golang-go install)
RUN curl -L https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 \
        -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Install trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# Copy and install Python deps first (better layer caching)
WORKDIR /agent
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source last (changes most frequently)
COPY . .

# Verify tools are available at build time
RUN bandit --version && \
    osv-scanner --version && \
    trufflehog --version

ENTRYPOINT ["python", "main.py"]