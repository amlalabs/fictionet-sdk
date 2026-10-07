"""Certificate authority for the adaptive web, copied from FakeWiki's.

Adapted from gaslight's ``ca.py`` (github.com/alexandra-sera-hsu/ai-hackathon).
The CA is generated once at image build time (``python ca.py DIR``) so the
agent image can trust it. The Rust world signs a certificate for each host
with it at the host's first handshake; ``CertAuthority`` below is the
Python version of that, kept from FakeWiki and unused here.
"""
from __future__ import annotations

import datetime as dt
import ssl
import sys
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Neutral name so an inspected chain doesn't announce the interception.
CA_NAME = "Internet Security Root CA"


def create_ca(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, content_commitment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    (directory / "ca.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()))
    (directory / "ca.key").chmod(0o600)
    (directory / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class CertAuthority:
    def __init__(self, directory: Path):
        self.key = serialization.load_pem_private_key((directory / "ca.key").read_bytes(), None)
        self.cert = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._tmp = Path(tempfile.mkdtemp(prefix="fictionet-leaf-"))

    def context_for(self, host: str) -> ssl.SSLContext:
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is None:
                ctx = self._mint(host)
                self._contexts[host] = ctx
            return ctx

    def _mint(self, host: str) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.cert.public_key()),
                critical=False)
            .sign(self.key, hashes.SHA256())
        )
        chain = self._tmp / f"{host}.pem"
        chain.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
            + self.cert.public_bytes(serialization.Encoding.PEM))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(chain)
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx


if __name__ == "__main__":
    create_ca(Path(sys.argv[1]))
