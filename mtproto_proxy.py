#!/usr/bin/env python3
"""
MTProto Proxy Server with DPI Bypass (Single Port)
===================================================
Accepts both MTProto and HTTPS on the same port (443).
- MTProto clients (secret starting with ee) -> Telegram
- HTTPS/Browser -> Real website (ya.ru, etc.)
"""

import asyncio
import hashlib
import logging
import os
import ssl
import struct
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
    host: str = "0.0.0.0"
    port: int = 443
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
    HEADER_SIZE = 8
    MAGIC_BYTE = 0xee  # Obfuscated MTProto

    @classmethod
    def is_mtproto(cls, data: bytes, secret: bytes) -> bool:
        """Check if data is MTProto by XORing header with secret."""
        if len(data) < 8:
            return False
        test_header = bytearray(data[:8])
        for i in range(8):
            test_header[i] ^= secret[i % len(secret)]
        return test_header[0] == cls.MAGIC_BYTE

    @classmethod
    def decode_length(cls, data: bytes, secret: bytes) -> int:
        """Decode frame length from header."""
        header = bytearray(data[:8])
        for i in range(8):
            header[i] ^= secret[i % len(secret)]
        return struct.unpack('<I', bytes(header[1:5]))[0]


# =============================================================================
# HTTP Handler
# =============================================================================

class HTTPHandler:
    @staticmethod
    def is_http(data: bytes) -> bool:
        """Check if data starts with HTTP method."""
        return data.startswith((b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS '))

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
    WEBSITES = [
        ("ya.ru", 443),
        ("mail.ru", 443),
        ("www.yandex.ru", 443),
        ("vk.com", 443),
        ("mamba.ru", 443),
    ]

    async def fetch(self, path: str, host_header: str = None) -> Tuple[int, dict, bytes]:
        """Fetch from real website."""
        for host, port in self.WEBSITES:
            try:
                return await self._fetch_from(host, port, path, host_header or host)
            except Exception as e:
                logger.debug(f"Failed to fetch from {host}: {e}")
                continue
        return 502, {}, b"<h1>502 Bad Gateway</h1>"

    async def _fetch_from(self, host: str, port: int, path: str, host_header: str) -> Tuple[int, dict, bytes]:
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
            f"Host: {host_header}\r\n"
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

        if b'\r\n\r\n' in response:
            header_part, body = response.split(b'\r\n\r\n', 1)
        else:
            header_part, body = response, b''

        lines = header_part.decode('utf-8', errors='ignore').split('\r\n')
        status = 200
        if lines:
            import re
            match = re.match(r'HTTP/[\d.]+ (\d+)', lines[0])
            if match:
                status = int(match.group(1))

        return status, {}, body


# =============================================================================
# TLS Handler - proxies full TLS connection to real website
# =============================================================================

class TLSProxy:
    """Proxies raw TLS connection to real website."""

    WEBSITES = [
        ("ya.ru", 443),
        ("mail.ru", 443),
        ("www.yandex.ru", 443),
        ("vk.com", 443),
        ("mamba.ru", 443),
    ]

    async def proxy(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        """Proxy TLS connection to real website."""
        for host, port in self.WEBSITES:
            try:
                await self._proxy_to(host, port, client_reader, client_writer)
                return
            except Exception as e:
                logger.debug(f"TLS proxy to {host} failed: {e}")
                continue
        logger.error("All TLS proxy targets failed")
        client_writer.close()

    async def _proxy_to(self, host: str, port: int, client_reader, client_writer):
        """Proxy to specific host."""
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=5.0
        )

        async def forward(src, dst, name):
            try:
                while True:
                    data = await src.read(4096)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception as e:
                logger.debug(f"{name} closed: {type(e).__name__}")
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            forward(client_reader, upstream_writer, "client->upstream"),
            forward(upstream_reader, client_writer, "upstream->client"),
            return_exceptions=True
        )


# =============================================================================
# Main Connection Handler
# =============================================================================

class ConnectionHandler:
    """Handles all connections - detects protocol and routes."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.website = RealWebsiteProxy()
        self.tls_proxy = TLSProxy()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Main handler - detect protocol from first bytes."""
        peer = writer.get_extra_info('peername')
        logger.info(f"[+] Connection from {peer[0]}:{peer[1]}")

        try:
            # Read more data to properly detect protocol
            # MTProto clients may send small packets first
            initial = b''
            timeout_count = 0
            while len(initial) < 64 and timeout_count < 3:  # Read at least 64 bytes
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                    if not chunk:
                        logger.info("[-] Connection closed by client")
                        writer.close()
                        return
                    initial += chunk
                    logger.info(f"[Data] Received {len(chunk)} bytes, total: {len(initial)} bytes: {initial[:32].hex()}")
                    
                    # Check if we have enough for detection
                    if len(initial) >= 8:
                        if MTProtoFrame.is_mtproto(initial, self.config.secret):
                            logger.info("[MTProto] Magic byte detected!")
                            break
                        if initial[0] == 0x16:  # TLS
                            logger.info("[TLS] TLS handshake detected")
                            break
                        if initial[0] == 0x05 and len(initial) >= 3:  # SOCKS5
                            logger.info("[SOCKS5] SOCKS5 detected")
                            break
                except asyncio.TimeoutError:
                    timeout_count += 1
                    logger.debug(f"Timeout {timeout_count}/3 waiting for data...")
                    if timeout_count >= 3:
                        break

            if not initial:
                logger.info("[-] No data received")
                writer.close()
                return

            logger.info(f"[Data] Final detection data ({len(initial)} bytes): {initial[:32].hex()}")

            # Detect protocol
            if MTProtoFrame.is_mtproto(initial, self.config.secret):
                logger.info("[MTProto] MTProto detected - proxying to Telegram")
                await self._handle_mtproto(reader, writer, initial)
            elif initial[0] == 0x16:  # TLS handshake
                logger.info("[TLS] TLS handshake detected - proxying to real website")
                await self._handle_tls(reader, writer, initial)
            elif initial[0] == 0x05 and len(initial) >= 3:  # SOCKS5
                logger.info("[SOCKS5] SOCKS5 detected")
                await self._handle_socks5(reader, writer, initial)
            elif HTTPHandler.is_http(initial):
                logger.info("[HTTP] HTTP request - serving website")
                await self._handle_http(reader, writer, initial)
            else:
                logger.info(f"[Unknown] Unknown protocol (first byte: {hex(initial[0])}) - closing")
                writer.close()

        except asyncio.TimeoutError:
            logger.error("[-] Connection timeout")
            writer.close()
        except Exception as e:
            logger.error(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()
            writer.close()

    async def _handle_socks5(self, reader, writer, initial: bytes):
        """Handle SOCKS5 connection."""
        try:
            # SOCKS5 handshake: client sends version(0x05), nmethods, methods
            # We respond with: version(0x05), method(0x00 = no auth)
            if len(initial) >= 3 and initial[0] == 0x05:
                nmethods = initial[1]
                # Respond with no authentication required
                writer.write(b'\x05\x00')
                await writer.drain()

                # Read SOCKS5 request
                request = await asyncio.wait_for(reader.read(262), timeout=5.0)
                if not request or len(request) < 10:
                    writer.close()
                    return

                # Parse request: version, cmd, rsv, atype, dst.addr, dst.port
                cmd = request[1]
                atype = request[3]

                # Determine destination
                offset = 4
                if atype == 1:  # IPv4
                    dst_ip = '.'.join(str(b) for b in request[offset:offset+4])
                    offset += 4
                elif atype == 3:  # Domain
                    dst_len = request[offset]
                    dst_ip = request[offset+1:offset+1+dst_len].decode()
                    offset += 1 + dst_len
                elif atype == 4:  # IPv6
                    dst_ip = ':'.join(hex(b)[2:] for b in request[offset:offset+16])
                    offset += 16
                else:
                    writer.close()
                    return

                dst_port = struct.unpack('>H', request[offset:offset+2])[0]

                logger.info(f"[SOCKS5] Request: cmd={cmd} addr={dst_ip}:{dst_port}")

                # Send success response
                response = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                writer.write(response)
                await writer.drain()

                # Connect to destination
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(dst_ip, dst_port),
                        timeout=5.0
                    )
                    logger.info(f"[SOCKS5] Connected to {dst_ip}:{dst_port}")

                    async def c2u():
                        try:
                            while True:
                                data = await reader.read(4096)
                                if not data:
                                    break
                                upstream_writer.write(data)
                                await upstream_writer.drain()
                        except Exception:
                            pass
                        finally:
                            try:
                                upstream_writer.close()
                            except Exception:
                                pass

                    async def u2c():
                        try:
                            while True:
                                data = await upstream_reader.read(4096)
                                if not data:
                                    break
                                writer.write(data)
                                await writer.drain()
                        except Exception:
                            pass
                        finally:
                            try:
                                writer.close()
                            except Exception:
                                pass

                    await asyncio.gather(c2u(), u2c(), return_exceptions=True)
                    logger.info("[-] SOCKS5 session ended")

                except Exception as e:
                    logger.error(f"[SOCKS5] Connection failed: {e}")
                    writer.close()

        except Exception as e:
            logger.error(f"[SOCKS5] Error: {e}")
            writer.close()

    async def _handle_mtproto(self, reader, writer, initial: bytes):
        """Handle MTProto connection."""
        try:
            tg_reader, tg_writer = await asyncio.open_connection(
                self.config.telegram_host,
                self.config.telegram_port
            )
            logger.info(f"[✓] Connected to Telegram {self.config.telegram_host}:{self.config.telegram_port}")

            tg_writer.write(initial)
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
                    logger.debug(f"C->T: {type(e).__name__}")

            async def t2c():
                try:
                    while True:
                        data = await tg_reader.read(4096)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception as e:
                    logger.debug(f"T->C: {type(e).__name__}")

            await asyncio.gather(c2t(), t2c(), return_exceptions=True)
            logger.info("[-] MTProto session ended")

        except Exception as e:
            logger.error(f"[-] MTProto error: {e}")
        finally:
            writer.close()

    async def _handle_tls(self, reader, writer, initial: bytes):
        """Handle TLS connection by proxying to real website."""
        try:
            # Connect to real website
            for host, port in self.tls_proxy.WEBSITES:
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=5.0
                    )
                    logger.info(f"[TLS] Connected to {host}:{port}")

                    # Send initial TLS ClientHello to upstream
                    upstream_writer.write(initial)
                    await upstream_writer.drain()

                    # Proxy bidirectionally
                    async def c2u():
                        try:
                            while True:
                                data = await reader.read(4096)
                                if not data:
                                    break
                                upstream_writer.write(data)
                                await upstream_writer.drain()
                        except Exception:
                            pass
                        finally:
                            try:
                                upstream_writer.close()
                            except Exception:
                                pass

                    async def u2c():
                        try:
                            while True:
                                data = await upstream_reader.read(4096)
                                if not data:
                                    break
                                writer.write(data)
                                await writer.drain()
                        except Exception:
                            pass
                        finally:
                            try:
                                writer.close()
                            except Exception:
                                pass

                    await asyncio.gather(c2u(), u2c(), return_exceptions=True)
                    logger.info("[-] TLS session ended")
                    return

                except Exception as e:
                    logger.debug(f"TLS proxy to {host} failed: {e}")
                    continue

            logger.error("[-] All TLS proxy targets failed")
            writer.close()

        except Exception as e:
            logger.error(f"[-] TLS error: {e}")
            writer.close()

    async def _handle_http(self, reader, writer, initial: bytes):
        """Handle HTTP request (after TLS termination or plain)."""
        try:
            method, path, headers = HTTPHandler.parse(initial)
            logger.info(f"[HTTP] {method} {path}")

            status, resp_headers, body = await self.website.fetch(path, headers.get('host'))
            logger.info(f"[HTTP] Response: {status} body_len={len(body)}")

            response = f"HTTP/1.1 {status} OK\r\n"
            for k, v in resp_headers.items():
                response += f"{k}: {v}\r\n"
            response += "\r\n"

            writer.write(response.encode())
            writer.write(body)
            await writer.drain()
            logger.info("[HTTP] Response sent")

        except Exception as e:
            logger.error(f"[-] HTTP error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# =============================================================================
# TLS Context (for reference, not used in raw mode)
# =============================================================================

class TLSContextManager:
    @staticmethod
    def create(cert_path: str, key_path: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)
        ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        return ctx

    @staticmethod
    def generate(cert_path: str, key_path: str, domain: str = "ya.ru"):
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
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.handler = ConnectionHandler(config)

    async def start(self):
        """Start proxy server on single port."""
        logger.info("=" * 60)
        logger.info("MTProto Proxy with DPI Bypass (Single Port)")
        logger.info("=" * 60)
        logger.info(f"Listening on: {self.config.host}:{self.config.port}")
        logger.info(f"Secret: {self.config.secret.hex()}")
        logger.info(f"Telegram: {self.config.telegram_host}:{self.config.telegram_port}")
        logger.info("=" * 60)

        # Generate cert if needed
        if not os.path.exists(self.config.tls_cert):
            TLSContextManager.generate(self.config.tls_cert, self.config.tls_key, self.config.fake_domain)

        # Start server WITHOUT SSL - we handle raw TCP
        server = await asyncio.start_server(
            self.handler.handle,
            self.config.host,
            self.config.port,
            reuse_port=True
        )

        addr = server.sockets[0].getsockname()
        logger.info(f"[✓] Server running on {addr[0]}:{addr[1]}")
        logger.info(f"[✓] MTProto clients -> Telegram")
        logger.info(f"[✓] Browser/DPI -> Real website")
        logger.info("=" * 60)

        async with server:
            await server.serve_forever()


# =============================================================================
# Main
# =============================================================================

def load_config(path: str = "config.json") -> Optional[dict]:
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
    cfg = load_config()

    if cfg:
        proxy = cfg.get('proxy', {})
        tls = cfg.get('tls', {})
        tg = cfg.get('telegram', {})
        dpi = cfg.get('dpi_bypass', {})

        config = ProxyConfig(
            host=proxy.get('host', '0.0.0.0'),
            port=proxy.get('port', 443),
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
        logger.error("Run with sudo or: sudo setcap 'cap_net_bind_service=+ep' $(which python3)")
