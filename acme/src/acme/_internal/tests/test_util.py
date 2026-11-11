"""Test utilities.

.. warning:: This module is not part of the public API.

"""
import datetime
import importlib.resources
import ipaddress
import os
from typing import Callable, Iterable, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
import josepy as jose
from josepy.util import ComparableECKey


def load_vector(*names):
    """Load contents of a test vector."""
    # luckily, resource_string opens file in binary mode
    vector_ref = importlib.resources.files(__package__).joinpath('testdata', *names)
    return vector_ref.read_bytes()


def _guess_loader(filename: str, loader_pem: Callable, loader_der: Callable) -> Callable:
    _, ext = os.path.splitext(filename)
    if ext.lower() == ".pem":
        return loader_pem
    elif ext.lower() == ".der":
        return loader_der
    else:  # pragma: no cover
        raise ValueError("Loader could not be recognized based on extension")


def load_cert(*names: str) -> x509.Certificate:
    """Load certificate."""
    loader = _guess_loader(
        names[-1], x509.load_pem_x509_certificate, x509.load_der_x509_certificate
    )
    return loader(load_vector(*names))


def load_csr(*names: str) -> x509.CertificateSigningRequest:
    """Load certificate request."""
    loader = _guess_loader(names[-1], x509.load_pem_x509_csr, x509.load_der_x509_csr)
    return loader(load_vector(*names))


def load_rsa_private_key(*names):
    """Load RSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return jose.ComparableRSAKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_ecdsa_private_key(*names):
    """Load ECDSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return ComparableECKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def generate_test_key():
    """Generate a short RSA private key for locally built test fixtures."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _san_general_names(
    dns_names: Iterable[str],
    ip_addresses: Iterable[str],
) -> list[x509.GeneralName]:
    return ([x509.DNSName(name) for name in dns_names]
            + [x509.IPAddress(ipaddress.ip_address(value))
               for value in ip_addresses])


def generate_test_csr(
    private_key,
    dns_names: Iterable[str] = (),
    ip_addresses: Iterable[str] = (),
) -> x509.CertificateSigningRequest:
    """Generate a CSR carrying the given DNS/IP SANs, signed by private_key."""
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName(
                _san_general_names(dns_names, ip_addresses)),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )


def generate_test_cert(
    private_key,
    dns_names: Iterable[str] = (),
    ip_addresses: Iterable[str] = (),
    *,
    issuer_key: Optional[CertificateIssuerPrivateKeyTypes] = None,
    common_name: Optional[str] = None,
    serial: int = 1,
    not_before: Optional[datetime.datetime] = None,
    validity: datetime.timedelta = datetime.timedelta(days=7),
) -> x509.Certificate:
    """Generate a short-lived leaf certificate for test fixtures.

    The certificate's public key is taken from ``private_key``; pass a
    different ``issuer_key`` to sign it with another key. SANs and an optional
    Common Name can be controlled independently of any CSR.
    """
    if not_before is None:
        not_before = datetime.datetime(2026, 1, 1)
    subject_attributes = []
    if common_name is not None:
        subject_attributes.append(
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject_attributes))
        .issuer_name(x509.Name(subject_attributes or [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Issuer")]))
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_before + validity)
    )
    general_names = _san_general_names(dns_names, ip_addresses)
    if general_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names), critical=False)
    signing_key = issuer_key if issuer_key is not None else private_key
    return builder.sign(signing_key, hashes.SHA256())


def generate_test_issuer(
    issuer_key,
    common_name: str = "Test Issuer",
) -> x509.Certificate:
    """Generate a self-signed issuer certificate for test chains."""
    name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(issuer_key.public_key())
        .serial_number(999)
        .not_valid_before(datetime.datetime(2026, 1, 1))
        .not_valid_after(datetime.datetime(2026, 2, 1))
        .sign(issuer_key, hashes.SHA256())
    )


def cert_chain_pem(certs: Iterable[x509.Certificate]) -> str:
    """Serialize certificates into one PEM fullchain string, leaf first."""
    return "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode()
        for cert in certs
    )
