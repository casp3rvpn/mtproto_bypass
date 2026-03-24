#!/usr/bin/env python3
"""
Configuration generator for MTProto Proxy with DPI Bypass
==========================================================
Generates configuration files and secrets for the proxy server.
"""

import json
import os
import secrets


def generate_secret() -> str:
    """Generate a random 32-byte secret for MTProto with dd prefix."""
    # MTProto secrets should start with dd or ee for proper detection
    # dd = secure MTProto, ee = fake TLS mode
    prefix = "dd"
    remaining = secrets.token_hex(31)  # 31 bytes = 62 hex chars
    return prefix + remaining


def generate_config(output_file: str = "config.json") -> dict:
    """Generate proxy configuration file."""
    config = {
        "proxy": {
            "host": "0.0.0.0",
            "port": 443,
            "secret": generate_secret(),
        },
        "tls": {
            "cert_path": "cert.pem",
            "key_path": "key.pem",
        },
        "telegram": {
            "host": "149.154.167.50",
            "port": 443,
        },
        "dpi_bypass": {
            "enabled": True,
            "real_website_host": "www.wikipedia.org",
            "real_website_port": 443,
            "fake_domain": "www.wikipedia.org",
            "timeout": 2.0,
        },
        "alternative_websites": [
            "www.wikipedia.org",
            "www.example.com",
            "www.cloudflare.com",
            "www.mozilla.org",
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"[✓] Configuration saved to {output_file}")
    print(f"[✓] Secret: {config['proxy']['secret']}")
    
    return config


def generate_systemd_service(output_file: str = "mtproto-proxy.service") -> str:
    """Generate systemd service file."""
    service = """[Unit]
Description=MTProto Proxy Server with DPI Bypass
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mtproto-proxy
ExecStart=/usr/bin/python3 /opt/mtproto-proxy/mtproto_proxy.py
Restart=always
RestartSec=10
LimitNOFILE=65535

# Allow binding to port 443
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"""
    
    with open(output_file, 'w') as f:
        f.write(service)
    
    print(f"[✓] Systemd service file saved to {output_file}")
    return service


def generate_dockerfile(output_file: str = "Dockerfile") -> str:
    """Generate Dockerfile."""
    dockerfile = """FROM python:3.11-slim

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
"""
    
    with open(output_file, 'w') as f:
        f.write(dockerfile)
    
    print(f"[✓] Dockerfile saved to {output_file}")
    return dockerfile


def generate_install_script(output_file: str = "install.sh") -> str:
    """Generate installation script."""
    script = """#!/bin/bash
# MTProto Proxy Installation Script

set -e

echo "=============================================="
echo "MTProto Proxy Installation"
echo "=============================================="

# Install dependencies
echo "[1/5] Installing Python dependencies..."
pip3 install -r requirements.txt

# Generate configuration
echo "[2/5] Generating configuration..."
python3 generate_config.py

# Set capabilities for port 443
echo "[3/5] Setting capabilities for port 443..."
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Generate SSL certificate
echo "[4/5] Generating SSL certificate..."
python3 -c "from mtproto_proxy import TLSContextManager; TLSContextManager.generate_self_signed_cert('cert.pem', 'key.pem')"

# Install systemd service
echo "[5/5] Installing systemd service..."
sudo cp mtproto-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable mtproto-proxy

echo ""
echo "=============================================="
echo "Installation complete!"
echo ""
echo "Start the proxy:"
echo "  sudo systemctl start mtproto-proxy"
echo ""
echo "Check status:"
echo "  sudo systemctl status mtproto-proxy"
echo ""
echo "View logs:"
echo "  sudo journalctl -u mtproto-proxy -f"
echo "=============================================="
"""
    
    with open(output_file, 'w') as f:
        f.write(script)
    
    os.chmod(output_file, 0o755)
    print(f"[✓] Installation script saved to {output_file}")
    return script


def main():
    """Main entry point."""
    print("=" * 60)
    print("MTProto Proxy Configuration Generator")
    print("=" * 60)
    
    generate_config()
    generate_systemd_service()
    generate_dockerfile()
    generate_install_script()
    
    print("=" * 60)
    print("Setup complete!")
    print("\nNext steps:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run installation: ./install.sh")
    print("3. Start proxy: sudo systemctl start mtproto-proxy")
    print("=" * 60)


if __name__ == "__main__":
    main()
