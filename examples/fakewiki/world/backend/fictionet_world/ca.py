"""Certificate authority for the FakeWiki world.

Adapted from gaslight's ``ca.py`` (github.com/alexandra-sera-hsu/ai-hackathon).
The CA is generated once at image build time (``python -m fictionet_world.ca``)
so the agent image can trust it. The world's Rust code makes the leaf certificates.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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


if __name__ == "__main__":
    create_ca(Path(sys.argv[1]))
