#!/usr/bin/env python3
"""
MTProto Proxy Server with Real Website DPI Bypass
==================================================
This proxy disguises MTProto traffic as regular HTTPS web traffic.
When DPI inspection is detected or browser access occurs, it serves
a REAL website by proxying to an actual web server.

Features:
- Full TLS/SSL encryption on port 443
- Real website serving for DPI/browser requests
- MTProto 2.0 protocol support for Telegram
- SNI (Server Name Indication) handling
- Advanced DPI bypass capabilities
"""

import asyncio
import hashlib
import os
import socket
import ssl
import struct
import re
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, List

import pyaes

# =============================================================================
# Configuration
# =============================================================================

@dataclass
class ProxyConfig:
    """Proxy server configuration."""
    host: str = "0.0.0.0"
    port: int = 443  # Standard HTTPS port
    secret: bytes = None
    tls_cert: str = "cert.pem"
    tls_key: str = "key.pem"

    # Real website configuration for DPI bypass (fallback list)
    real_website_host: str = "ya.ru"
    real_website_port: int = 443
    fake_domain: str = "ya.ru"
    fake_server: str = "nginx/1.24.0"

    # Telegram relay
    telegram_host: str = "149.154.167.50"
    telegram_port: int = 443

    # DPI detection settings
    dpi_timeout: float = 2.0  # Quick timeout for DPI probes
    enable_dpi_bypass: bool = True
    
    def __post_init__(self):
        if self.secret is None:
            self.secret = os.urandom(32)


# =============================================================================
# SNI Parser - Extract domain from TLS ClientHello
# =============================================================================

class SNIParser:
    """Extract Server Name Indication from TLS ClientHello."""
    
    @staticmethod
    def parse_sni(data: bytes) -> Optional[str]:
        """Extract SNI hostname from TLS ClientHello."""
        try:
            if len(data) < 5 or data[0] != 0x16:  # Not TLS handshake
                return None
            
            # TLS record header
            record_type = data[0]
            version = data[1:3]
            record_length = struct.unpack('>H', data[3:5])[0]
            
            if len(data) < 5 + record_length:
                return None
            
            record_data = data[5:5 + record_length]
            
            # ClientHello handshake
            if record_data[0] != 0x01:  # Not ClientHello
                return None
            
            # Skip handshake header (4 bytes)
            hello_data = record_data[5:]
            
            # Skip session ID
            session_id_length = hello_data[34]
            offset = 35 + session_id_length
            
            # Skip cipher suites
            cipher_length = struct.unpack('>H', hello_data[offset:offset+2])[0]
            offset += 2 + cipher_length
            
            # Skip compression methods
            compression_length = hello_data[offset]
            offset += 1 + compression_length
            
            # Parse extensions
            if offset + 2 > len(hello_data):
                return None
            
            extensions_length = struct.unpack('>H', hello_data[offset:offset+2])[0]
            offset += 2
            
            extensions_data = hello_data[offset:offset + extensions_length]
            
            # Find SNI extension (type 0)
            ext_offset = 0
            while ext_offset + 4 <= len(extensions_data):
                ext_type = struct.unpack('>H', extensions_data[ext_offset:ext_offset+2])[0]
                ext_length = struct.unpack('>H', extensions_data[ext_offset+2:ext_offset+4])[0]
                
                if ext_type == 0 and ext_length > 5:  # SNI extension
                    # Parse SNI list
                    sni_list_length = struct.unpack('>H', extensions_data[ext_offset+4:ext_offset+6])[0]
                    sni_data = extensions_data[ext_offset+6:ext_offset+4+ext_length]
                    
                    # Get first hostname
                    if len(sni_data) >= 3:
                        name_type = sni_data[0]
                        if name_type == 0:  # DNS name
                            name_length = struct.unpack('>H', sni_data[1:3])[0]
                            hostname = sni_data[3:3+name_length].decode('utf-8', errors='ignore')
                            return hostname
                
                ext_offset += 4 + ext_length
            
            return None
            
        except Exception:
            return None


# =============================================================================
# Real Website Proxy - Fetches real website content
# =============================================================================

class RealWebsiteProxy:
    """Proxies requests to a real website for DPI bypass."""
    
    # List of fallback websites for DPI bypass
    WEBSITES = [
        ("ya.ru", 443),
        ("mail.ru", 443),
        ("www.yandex.ru", 443),
        ("vk.com", 443),
        ("mamba.ru", 443),
    ]

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.session = None

    async def fetch_website(self, host: str, path: str, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """Fetch content from real website with fallback support."""
        for website_host, website_port in self.WEBSITES:
            try:
                return await self._fetch_from_host(website_host, website_port, path)
            except Exception as e:
                print(f"[-] Failed to fetch from {website_host}: {e}")
                continue
        
        # All websites failed, return error page
        return 502, {}, b"<h1>502 Bad Gateway</h1>"
    
    async def _fetch_from_host(self, host: str, port: int, path: str) -> Tuple[int, Dict[str, str], bytes]:
        """Fetch content from specific host."""
        # Create SSL context for upstream connection
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Connect with timeout
        try:
            conn_future = asyncio.open_connection(host, port, ssl=ssl_context)
            reader, writer = await asyncio.wait_for(conn_future, timeout=5.0)
        except asyncio.TimeoutError:
            raise Exception(f"Connection timeout to {host}")
        
        try:
            # Build HTTP request
            request = f"GET {path} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            request += "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8\r\n"
            request += "Accept-Encoding: gzip, deflate\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            writer.write(request.encode('utf-8'))
            await writer.drain()
            
            # Read response with timeout
            response = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
        
        # Parse response
        return self._parse_response(response)
    
    def _parse_response(self, response: bytes) -> Tuple[int, Dict[str, str], bytes]:
        """Parse HTTP response from real website."""
        try:
            # Split headers and body
            if b'\r\n\r\n' in response:
                header_part, body = response.split(b'\r\n\r\n', 1)
            else:
                header_part = response
                body = b''
            
            # Parse status line
            lines = header_part.decode('utf-8', errors='ignore').split('\r\n')
            status_line = lines[0]
            status_match = re.match(r'HTTP/[\d.]+ (\d+)', status_line)
            status = int(status_match.group(1)) if status_match else 200
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    if key not in ['transfer-encoding', 'connection']:
                        headers[key] = value
            
            return status, headers, body
            
        except Exception:
            return 500, {}, b"<h1>500 Internal Server Error</h1>"
    
    async def proxy_full_connection(self, reader: asyncio.StreamReader,
                                     writer: asyncio.StreamWriter) -> None:
        """Proxy entire HTTPS connection to real website with fallback."""
        for host, port in self.WEBSITES:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl.create_default_context()),
                    timeout=5.0
                )
                
                async def forward(source, dest):
                    try:
                        while True:
                            data = await source.read(4096)
                            if not data:
                                break
                            dest.write(data)
                            await dest.drain()
                    except Exception:
                        pass
                    finally:
                        try:
                            dest.close()
                        except Exception:
                            pass
                
                await asyncio.gather(
                    forward(reader, upstream_writer),
                    forward(upstream_reader, writer),
                    return_exceptions=True
                )
                return  # Success, exit the function
                
            except Exception as e:
                print(f"[-] Full proxy failed to {host}: {e}")
                continue
        
        print(f"[-] All websites failed for full proxy")
        try:
            writer.close()
        except Exception:
            pass


# =============================================================================
# MTProto Protocol
# =============================================================================

class MTProtoFrame:
    """MTProto frame handling."""
    
    HEADER_SIZE = 8
    MAGIC_BYTE = 0xee
    
    @classmethod
    def encode(cls, data: bytes, secret: bytes) -> bytes:
        """Encode MTProto frame with obfuscation."""
        length = len(data)
        header = bytearray(cls.HEADER_SIZE)
        header[0] = cls.MAGIC_BYTE
        header[1:5] = struct.pack('<I', length)
        header[4:8] = struct.pack('<I', length)
        
        for i in range(cls.HEADER_SIZE):
            header[i] ^= secret[i % len(secret)]
        
        return bytes(header) + data
    
    @classmethod
    def decode_header(cls, data: bytes, secret: bytes) -> Tuple[int, bytes]:
        """Decode frame header and return length."""
        if len(data) < cls.HEADER_SIZE:
            return 0, data
        
        header = bytearray(data[:cls.HEADER_SIZE])
        for i in range(cls.HEADER_SIZE):
            header[i] ^= secret[i % len(secret)]
        
        if header[0] != cls.MAGIC_BYTE:
            return 0, data
        
        length = struct.unpack('<I', bytes(header[1:5]))[0]
        return length, data[cls.HEADER_SIZE:]


# =============================================================================
# HTTP Handler
# =============================================================================

class HTTPHandler:
    """Handles HTTP requests."""
    
    @staticmethod
    def parse_request(data: bytes) -> Tuple[str, str, dict]:
        """Parse HTTP request."""
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            if not lines:
                return '', '', {}
            
            parts = lines[0].split(' ')
            method = parts[0] if len(parts) > 0 else ''
            path = parts[1] if len(parts) > 1 else '/'
            
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            return method, path, headers
        except Exception:
            return '', '', {}
    
    @classmethod
    def is_http_request(cls, data: bytes) -> bool:
        """Check if data looks like HTTP request."""
        try:
            text = data.decode('utf-8', errors='ignore')
            return text.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ', 'OPTIONS '))
        except Exception:
            return False


# =============================================================================
# Connection Handler
# =============================================================================

class ConnectionHandler:
    """Handles connections with DPI bypass."""
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.website_proxy = RealWebsiteProxy(config)
    
    async def handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        """Main connection handler with protocol detection."""
        peer_addr = writer.get_extra_info('peername')
        print(f"[+] Connection from {peer_addr[0]}:{peer_addr[1]}")
        
        try:
            # Read initial data with timeout for DPI detection
            try:
                initial_data = await asyncio.wait_for(
                    reader.read(65536),
                    timeout=self.config.dpi_timeout
                )
            except asyncio.TimeoutError:
                print(f"[-] Timeout - possible DPI probe")
                writer.close()
                return
            
            if not initial_data:
                writer.close()
                return
            
            # Detect protocol
            if self._is_dpi_probe(initial_data):
                print(f"[DPI] DPI probe detected - serving real website")
                await self._handle_dpi_bypass(reader, writer, initial_data)
            elif HTTPHandler.is_http_request(initial_data):
                print(f"[Web] HTTP request - serving real website")
                await self._handle_http_request(reader, writer, initial_data)
            elif self._is_mtproto(initial_data):
                print(f"[MTProto] MTProto detected")
                await self._handle_mtproto(reader, writer, initial_data)
            else:
                # Default: serve real website (safest for DPI)
                print(f"[Web] Unknown traffic - serving real website")
                await self._handle_dpi_bypass(reader, writer, initial_data)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[-] Error: {e}")
            try:
                writer.close()
            except Exception:
                pass
    
    def _is_dpi_probe(self, data: bytes) -> bool:
        """Detect potential DPI probes."""
        # Check for common DPI patterns
        if len(data) < 5:
            return True
        
        # Check for incomplete TLS handshake
        if data[0] == 0x16 and len(data) < 50:
            return True
        
        # Check for HTTP without proper headers
        try:
            text = data.decode('utf-8', errors='ignore')
            if text.startswith('GET') and 'Host:' not in text:
                return True
        except Exception:
            pass
        
        return False
    
    def _is_mtproto(self, data: bytes) -> bool:
        """Detect MTProto handshake."""
        if len(data) < 8:
            return False
        
        test_header = bytearray(data[:8])
        for i in range(8):
            test_header[i] ^= self.config.secret[i % len(self.config.secret)]
        
        return test_header[0] == 0xee
    
    async def _handle_dpi_bypass(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter,
                                  initial_data: bytes) -> None:
        """Handle DPI bypass by proxying to real website."""
        try:
            # Extract SNI to know what domain client requested
            sni_host = SNIParser.parse_sni(initial_data)
            
            if sni_host:
                print(f"[SNI] Requested domain: {sni_host}")
            
            # Full TLS proxy to real website
            await self.website_proxy.proxy_full_connection(reader, writer)
            print(f"[✓] DPI bypass completed")
            
        except Exception as e:
            print(f"[-] DPI bypass error: {e}")
            try:
                writer.close()
            except Exception:
                pass
    
    async def _handle_http_request(self, reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter,
                                    initial_data: bytes) -> None:
        """Handle plain HTTP request (after TLS termination or direct HTTP)."""
        try:
            method, path, headers = HTTPHandler.parse_request(initial_data)
            
            # Fetch from real website
            status, resp_headers, body = await self.website_proxy.fetch_website(
                headers.get('host', self.config.real_website_host),
                path,
                headers
            )
            
            # Send response
            response = f"HTTP/1.1 {status} OK\r\n"
            for key, value in resp_headers.items():
                response += f"{key}: {value}\r\n"
            response += "\r\n"
            
            writer.write(response.encode('utf-8'))
            writer.write(body)
            await writer.drain()
            
        except Exception as e:
            print(f"[-] HTTP error: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass
    
    async def _handle_mtproto(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter,
                               initial_data: bytes) -> None:
        """Handle MTProto proxy connection."""
        telegram_writer = None
        
        try:
            telegram_reader, telegram_writer = await asyncio.open_connection(
                self.config.telegram_host,
                self.config.telegram_port
            )
            print(f"[✓] Connected to Telegram")
            
            telegram_writer.write(initial_data)
            await telegram_writer.drain()
            
            await self._proxy_mtproto(reader, writer, telegram_reader, telegram_writer)
            
        except Exception as e:
            print(f"[-] MTProto error: {e}")
        finally:
            if telegram_writer:
                try:
                    telegram_writer.close()
                except Exception:
                    pass
            try:
                writer.close()
            except Exception:
                pass
    
    async def _proxy_mtproto(self, client_reader, client_writer,
                              telegram_reader, telegram_writer) -> None:
        """Proxy MTProto data bidirectionally."""
        
        async def client_to_telegram():
            try:
                while True:
                    data = await client_reader.read(4096)
                    if not data:
                        break
                    telegram_writer.write(data)
                    await telegram_writer.drain()
            except Exception as e:
                print(f"[-] C->T: {e}")
        
        async def telegram_to_client():
            try:
                while True:
                    data = await telegram_reader.read(4096)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
            except Exception as e:
                print(f"[-] T->C: {e}")
        
        await asyncio.gather(
            client_to_telegram(),
            telegram_to_client(),
            return_exceptions=True
        )


# =============================================================================
# TLS Context Manager
# =============================================================================

class TLSContextManager:
    """Manages TLS/SSL context."""
    
    @staticmethod
    def create_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
        """Create SSL context for HTTPS."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        context.load_cert_chain(cert_path, key_path)
        context.set_ciphers(
            'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20'
        )

        # OP_NO_SSLv2 and OP_NO_SSLv3 are set by default in Python 3.10+
        # TLS 1.0/1.1 are disabled via minimum_version=TLSv1_2
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3

        # Enable SNI
        context.sni_callback = TLSContextManager._sni_callback

        return context
    
    @staticmethod
    def _sni_callback(sslsock, server_name, sslcontext):
        """Handle SNI callback."""
        if server_name:
            print(f"[SNI] Client requested: {server_name}")
    
    @staticmethod
    def generate_self_signed_cert(cert_path: str, key_path: str,
                                   domain: str = "ya.ru") -> None:
        """Generate self-signed certificate."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
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
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName(f"*.{domain}"),
            ]),
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
        
        print(f"[✓] Generated certificate for {domain}")


# =============================================================================
# Main Proxy Server
# =============================================================================

class MTProtoProxyServer:
    """MTProto proxy with real website DPI bypass."""
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.handler = ConnectionHandler(config)
        self.server = None
    
    async def start(self) -> None:
        """Start the proxy server."""
        print("=" * 60)
        print("MTProto Proxy with Real Website DPI Bypass")
        print("=" * 60)
        print(f"Listening on: {self.config.host}:{self.config.port}")
        print(f"Real website: {self.config.real_website_host}")
        print(f"Telegram: {self.config.telegram_host}:{self.config.telegram_port}")
        print(f"Secret: {self.config.secret.hex()}")
        print("=" * 60)
        
        # Generate certificates
        if not os.path.exists(self.config.tls_cert):
            TLSContextManager.generate_self_signed_cert(
                self.config.tls_cert,
                self.config.tls_key,
                self.config.fake_domain
            )
        
        ssl_context = TLSContextManager.create_ssl_context(
            self.config.tls_cert,
            self.config.tls_key
        )
        
        self.server = await asyncio.start_server(
            self.handler.handle_connection,
            self.config.host,
            self.config.port,
            ssl=ssl_context,
            reuse_port=True
        )
        
        addr = self.server.sockets[0].getsockname()
        print(f"[✓] Server running on {addr[0]}:{addr[1]}")
        print(f"[✓] Port 443 - Standard HTTPS")
        print(f"[✓] DPI probes → Real website ({self.config.real_website_host})")
        print(f"[✓] MTProto clients → Telegram")
        print("=" * 60)
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self) -> None:
        """Stop the server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("[✓] Server stopped")


# =============================================================================
# Entry Point
# =============================================================================

async def main():
    """Main entry point."""
    secret = os.urandom(32)

    config = ProxyConfig(
        host="0.0.0.0",
        port=443,
        secret=secret,
        tls_cert="cert.pem",
        tls_key="key.pem",
        real_website_host="ya.ru",
        fake_domain="ya.ru",
    )

    server = MTProtoProxyServer(config)

    try:
        await server.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        await server.stop()
    except PermissionError:
        print("[!] Error: Port 443 requires root privileges")
        print("    Run with: sudo python3 mtproto_proxy.py")
        print("    Or use setcap: sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3.11")


if __name__ == "__main__":
    asyncio.run(main())
