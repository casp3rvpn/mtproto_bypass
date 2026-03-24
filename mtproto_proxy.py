#!/usr/bin/env python3
"""
MTProto Proxy Server with Real Website DPI Bypass
==================================================
Supports:
- Plain MTProto connections (for Telegram clients)
- TLS/HTTPS connections (for browsers/DPI - serves real website)
"""

import asyncio
import hashlib
import logging
import os
import socket
import ssl
import struct
import re
import sys
from dataclasses import dataclass
from typing import Optional, Tuple, Dict

import pyaes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class ProxyConfig:
    """Proxy server configuration."""
    host: str = "0.0.0.0"
    port: int = 443
    mtproto_port: int = 3128  # Separate port for plain MTProto
    secret: bytes = None
    tls_cert: str = "cert.pem"
    tls_key: str = "key.pem"
    real_website_host: str = "ya.ru"
    real_website_port: int = 443
    fake_domain: str = "ya.ru"
    telegram_host: str = "149.154.167.50"
    telegram_port: int = 443

    def __post_init__(self):
        if self.secret is None:
            self.secret = os.urandom(32)


# =============================================================================
# MTProto Protocol
# =============================================================================

class MTProtoFrame:
    """MTProto frame handling."""
    HEADER_SIZE = 8
    MAGIC_BYTE = 0xee

    @classmethod
    def is_mtproto(cls, data: bytes, secret: bytes) -> bool:
        """Check if data is MTProto."""
        if len(data) < 8:
            return False
        test_header = bytearray(data[:8])
        for i in range(8):
            test_header[i] ^= secret[i % len(secret)]
        return test_header[0] == cls.MAGIC_BYTE


# =============================================================================
# HTTP Handler
# =============================================================================

class HTTPHandler:
    """Handles HTTP requests."""

    @staticmethod
    def is_http(data: bytes) -> bool:
        """Check if data is HTTP request."""
        try:
            return data.startswith((b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS '))
        except Exception:
            return False

    @staticmethod
    def parse(data: bytes) -> Tuple[str, str, dict]:
        """Parse HTTP request."""
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            parts = lines[0].split(' ')
            method = parts[0] if len(parts) > 0 else ''
            path = parts[1] if len(parts) > 1 else '/'
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
            return method, path, headers
        except Exception:
            return '', '/', {}


# =============================================================================
# Real Website Proxy
# =============================================================================

class RealWebsiteProxy:
    """Proxies to real website."""

    WEBSITES = [
        ("ya.ru", 443),
        ("mail.ru", 443),
        ("www.yandex.ru", 443),
        ("vk.com", 443),
        ("mamba.ru", 443),
    ]

    async def fetch(self, path: str) -> Tuple[int, dict, bytes]:
        """Fetch from real website."""
        for host, port in self.WEBSITES:
            try:
                return await self._fetch_from(host, port, path)
            except Exception as e:
                logger.debug(f"Failed to fetch from {host}: {e}")
                continue
        return 502, {}, b"<h1>502 Bad Gateway</h1>"

    async def _fetch_from(self, host: str, port: int, path: str) -> Tuple[int, dict, bytes]:
        """Fetch from specific host."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=5.0
        )

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Accept-Language: ru-RU,ru;q=0.9\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(65536), timeout=10.0)
        writer.close()

        # Parse response
        if b'\r\n\r\n' in response:
            header_part, body = response.split(b'\r\n\r\n', 1)
        else:
            header_part, body = response, b''

        lines = header_part.decode('utf-8', errors='ignore').split('\r\n')
        status = 200
        if lines:
            match = re.match(r'HTTP/[\d.]+ (\d+)', lines[0])
            if match:
                status = int(match.group(1))

        return status, {}, body


# =============================================================================
# Connection Handlers
# =============================================================================

class PlainConnectionHandler:
    """Handles plain (non-TLS) connections - MTProto from Telegram."""

    def __init__(self, config: ProxyConfig):
        self.config = config

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle plain connection."""
        peer = writer.get_extra_info('peername')
        logger.info(f"[+] Plain connection from {peer[0]}:{peer[1]}")

        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not data:
                writer.close()
                return

            logger.info(f"[Data] Received {len(data)} bytes: {data[:20].hex()}")

            if MTProtoFrame.is_mtproto(data, self.config.secret):
                logger.info("[MTProto] MTProto detected - connecting to Telegram")
                await self._proxy_to_telegram(reader, writer, data)
            else:
                logger.info("[Unknown] Unknown protocol - closing")
                writer.close()

        except asyncio.TimeoutError:
            logger.error("[-] Timeout reading data")
            writer.close()
        except Exception as e:
            logger.error(f"[-] Error: {e}")
            writer.close()

    async def _proxy_to_telegram(self, reader, writer, initial_data: bytes):
        """Proxy to Telegram."""
        try:
            tg_reader, tg_writer = await asyncio.open_connection(
                self.config.telegram_host,
                self.config.telegram_port
            )
            logger.info(f"[✓] Connected to Telegram {self.config.telegram_host}:{self.config.telegram_port}")

            tg_writer.write(initial_data)
            await tg_writer.drain()

            async def c2t():
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data:
                            break
                        tg_writer.write(data)
                        await tg_writer.drain()
                except Exception as e:
                    logger.debug(f"C->T closed: {type(e).__name__}")

            async def t2c():
                try:
                    while True:
                        data = await tg_reader.read(4096)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception as e:
                    logger.debug(f"T->C closed: {type(e).__name__}")

            await asyncio.gather(c2t(), t2c(), return_exceptions=True)
            logger.info("[-] MTProto session ended")

        except Exception as e:
            logger.error(f"[-] MTProto error: {e}")
        finally:
            writer.close()


class TLSConnectionHandler:
    """Handles TLS connections - browsers/DPI."""

    def __init__(self, config: ProxyConfig, ssl_context: ssl.SSLContext):
        self.config = config
        self.ssl_context = ssl_context
        self.website = RealWebsiteProxy()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle TLS connection."""
        peer = writer.get_extra_info('peername')
        logger.info(f"[+] TLS connection from {peer[0]}:{peer[1]}")

        try:
            # TLS handshake is automatic with asyncio.start_server(ssl=...)
            # Data is already decrypted
            data = await asyncio.wait_for(reader.read(65536), timeout=5.0)
            if not data:
                writer.close()
                return

            logger.info(f"[TLS Data] Received {len(data)} bytes")

            if HTTPHandler.is_http(data):
                method, path, headers = HTTPHandler.parse(data)
                logger.info(f"[HTTP] {method} {path}")

                status, resp_headers, body = await self.website.fetch(path)
                logger.info(f"[HTTP] Response: {status} body_len={len(body)}")

                response = f"HTTP/1.1 {status} OK\r\n"
                for k, v in resp_headers.items():
                    response += f"{k}: {v}\r\n"
                response += "\r\n"

                writer.write(response.encode())
                writer.write(body)
                await writer.drain()
                logger.info("[HTTP] Response sent")
            else:
                logger.info("[TLS] Unknown TLS data - closing")

        except Exception as e:
            logger.error(f"[-] TLS error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# =============================================================================
# TLS Context
# =============================================================================

class TLSContextManager:
    """Manages TLS context."""

    @staticmethod
    def create(cert_path: str, key_path: str) -> ssl.SSLContext:
        """Create SSL context."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)
        ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        return ctx

    @staticmethod
    def generate(cert_path: str, key_path: str, domain: str = "ya.ru"):
        """Generate self-signed cert."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wikimedia Foundation"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        ).sign(key, hashes.SHA256())

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logger.info(f"[✓] Generated certificate for {domain}")


# =============================================================================
# Proxy Server
# =============================================================================

class MTProtoProxyServer:
    """MTProto proxy with separate ports for plain and TLS."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.plain_handler = PlainConnectionHandler(config)
        self.tls_context = TLSContextManager.create(config.tls_cert, config.tls_key)
        self.tls_handler = TLSConnectionHandler(config, self.tls_context)

    async def start(self):
        """Start both plain and TLS servers."""
        logger.info("=" * 60)
        logger.info("MTProto Proxy with DPI Bypass")
        logger.info("=" * 60)
        logger.info(f"Plain MTProto port: {self.config.mtproto_port}")
        logger.info(f"TLS/HTTPS port: {self.config.port}")
        logger.info(f"Secret: {self.config.secret.hex()}")
        logger.info(f"Telegram: {self.config.telegram_host}:{self.config.telegram_port}")
        logger.info("=" * 60)

        # Generate cert if needed
        if not os.path.exists(self.config.tls_cert):
            TLSContextManager.generate(self.config.tls_cert, self.config.tls_key, self.config.fake_domain)

        # Start plain server (for Telegram MTProto)
        plain_server = await asyncio.start_server(
            self.plain_handler.handle,
            self.config.host,
            self.config.mtproto_port,
            reuse_port=True
        )

        # Start TLS server (for browsers/DPI)
        tls_server = await asyncio.start_server(
            self.tls_handler.handle,
            self.config.host,
            self.config.port,
            ssl=self.tls_context,
            reuse_port=True
        )

        logger.info(f"[✓] Plain server on {self.config.host}:{self.config.mtproto_port}")
        logger.info(f"[✓] TLS server on {self.config.host}:{self.config.port}")
        logger.info("=" * 60)

        async with plain_server, tls_server:
            await asyncio.gather(
                plain_server.serve_forever(),
                tls_server.serve_forever()
            )


# =============================================================================
# Main
# =============================================================================

def load_config(path: str = "config.json") -> Optional[dict]:
    """Load config from file."""
    import json
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Config error: {e}")
        return None


async def main():
    """Main entry point."""
    cfg = load_config()

    if cfg:
        proxy = cfg.get('proxy', {})
        tls = cfg.get('tls', {})
        tg = cfg.get('telegram', {})
        dpi = cfg.get('dpi_bypass', {})

        config = ProxyConfig(
            host=proxy.get('host', '0.0.0.0'),
            port=proxy.get('port', 443),
            mtproto_port=proxy.get('mtproto_port', 3128),
            secret=bytes.fromhex(proxy.get('secret', os.urandom(32).hex())),
            tls_cert=tls.get('cert_path', 'cert.pem'),
            tls_key=tls.get('key_path', 'key.pem'),
            real_website_host=dpi.get('real_website_host', 'ya.ru'),
            fake_domain=dpi.get('fake_domain', 'ya.ru'),
            telegram_host=tg.get('host', '149.154.167.50'),
            telegram_port=tg.get('port', 443),
        )
        logger.info("[✓] Loaded config.json")
    else:
        config = ProxyConfig()
        logger.info("[✓] Using defaults")

    server = MTProtoProxyServer(config)
    await server.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n[!] Shutting down...")
    except PermissionError as e:
        logger.error(f"[!] Permission error: {e}")
        logger.error("Run with sudo or set capabilities: sudo setcap 'cap_net_bind_service=+ep' $(which python3)")
