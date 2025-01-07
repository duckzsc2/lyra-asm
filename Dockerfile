# Use Alpine Linux as base image
FROM golang:1.21-alpine

# Install required dependencies
RUN apk add --no-cache git build-base python3

# Install nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Add the Go bin directory to PATH
ENV PATH="/root/go/bin:${PATH}"

# Create a working directory
WORKDIR /app

# Create directories and copy files
RUN mkdir -p /app/templates /app/landing
COPY templates/report_template.html /app/templates/
COPY templates/styles.css /app/templates/
COPY landing/index.html /app/landing/
COPY landing/landing.css /app/landing/
COPY recon.py /app/
RUN chmod +x /app/recon.py

# Set the entrypoint to sh
ENTRYPOINT ["sh"] 