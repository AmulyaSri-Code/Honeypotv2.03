FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies if required (e.g. for ML libraries or compilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Expose required ports
# SSH (2222), FTP (2121), HTTP (8080), Telnet (2323), NC (4444), Dashboard API (5050)
EXPOSE 2222 2121 8080 2323 4444 5050

# Run the honeypot
CMD ["python", "main.py"]
