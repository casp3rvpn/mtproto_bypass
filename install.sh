#!/bin/bash
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
