FROM python:3.12-slim

RUN apt-get update && apt-get install -y curl git && rm -rf /var/lib/apt/lists/*

# Install bandit first
RUN pip install bandit

# Install trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install osv-scanner via Go (if available) or use pip
RUN apt-get update && apt-get install -y golang-go && rm -rf /var/lib/apt/lists/* && \
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest && \
    cp /root/go/bin/osv-scanner /usr/local/bin/

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . /agent
WORKDIR /agent

ENTRYPOINT ["python", "main.py"]