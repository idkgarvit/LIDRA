import logging
import os
import ssl
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TLSInterceptor:
    def __init__(self, config: dict = None):
        self._config = config or {}
        self._ca_cert_path = Path(self._config.get("ca_cert", "./state/ca/ca_cert.pem"))
        self._ca_key_path = Path(self._config.get("ca_key", "./state/ca/ca_key.pem"))
        self._ca_cert = None
        self._ca_key = None
        self._proxy_port = self._config.get("proxy_port", 8443)
        self._running = False
        self._ensure_ca()

    def _ensure_ca(self):
        self._ca_cert_path.parent.mkdir(parents=True, exist_ok=True)
        if self._ca_cert_path.exists() and self._ca_key_path.exists():
            self._ca_cert = self._ca_cert_path.read_text()
            self._ca_key = self._ca_key_path.read_text()
            logger.info(f"[TLS-Proxy] Using existing CA: {self._ca_cert_path}")
            return
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime as dt

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LIDRA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "LIDRA TLS Interceptor CA"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(dt.datetime.utcnow())
                .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256())
            )
            self._ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            self._ca_key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
            self._ca_cert = self._ca_cert_path.read_text()
            self._ca_key = self._ca_key_path.read_text()
            logger.info(f"[TLS-Proxy] Generated CA: {self._ca_cert_path}")
        except ImportError:
            logger.warning("[TLS-Proxy] cryptography not installed; cert generation disabled")
        except Exception as e:
            logger.warning(f"[TLS-Proxy] CA generation failed: {e}")

    def should_intercept(self, sni: str, dst_ip: str) -> bool:
        if not sni and not dst_ip:
            return False
        explicit = self._config.get("decrypt_snis", [])
        if explicit and sni:
            return any(p in sni for p in explicit)
        ip_ranges = self._config.get("decrypt_ip_ranges", [])
        if ip_ranges and dst_ip:
            for cidr in ip_ranges:
                ip_int = self._ip_to_int(dst_ip)
                network, prefix = cidr.split("/")
                net_int = self._ip_to_int(network)
                mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
                if (ip_int & mask) == (net_int & mask):
                    return True
        return True

    @staticmethod
    def _ip_to_int(ip: str) -> int:
        parts = ip.split(".")
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
