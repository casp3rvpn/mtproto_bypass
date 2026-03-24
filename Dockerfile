FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY mtproto_proxy.py .
COPY config.json .

# Expose HTTPS port
EXPOSE 443

# Run the proxy
CMD ["python3", "mtproto_proxy.py"]
