"""Crypto utilities."""
import enum
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import re
from types import ModuleType
import typing
from typing import Any
from typing import Optional
from typing import Union
import warnings
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec, ed25519, ed448, types
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import crypto

logger = logging.getLogger(__name__)


# https://github.com/pyca/cryptography/blob/1eab7a67dcc34b568e3c0df64e6222a2ac74b1ee/src/cryptography/utils.py#L66-L113
class _ClientDeprecationModule(ModuleType):
    """
    Internal class delegating to a module, and displaying warnings when attributes
    related to deprecated attributes in the acme.client module.
    """
    def __init__(self, module: ModuleType) -> None:
        super().__init__(module.__name__)
        self.__dict__['_module'] = module

    def __getattr__(self, attr: str) -> Any:
        if attr == 'Format':
            warnings.warn("acme.crypto_util.Format is deprecated and will be removed in "
                "the next major release.", DeprecationWarning)
        return getattr(self._module, attr)

    def __setattr__(self, attr: str, value: Any) -> None:  # pragma: no cover
        setattr(self._module, attr, value)

    def __delattr__(self, attr: str) -> None:  # pragma: no cover
        delattr(self._module, attr)

    def __dir__(self) -> list[str]:  # pragma: no cover
        return ['_module'] + dir(self._module)


# Patching ourselves to warn about deprecation and planned removal of some elements in the module.
sys.modules[__name__] = _ClientDeprecationModule(sys.modules[__name__])


class Format(enum.IntEnum):
    """File format to be used when parsing or serializing X.509 structures. Deprecated.

    Backwards compatible with the `FILETYPE_ASN1` and `FILETYPE_PEM` constants
    from pyOpenSSL.
    """
    DER = crypto.FILETYPE_ASN1
    PEM = crypto.FILETYPE_PEM

    def to_cryptography_encoding(self) -> Encoding:
        """Converts the Format to the corresponding cryptography `Encoding`.
        """
        if self == Format.DER:
            return Encoding.DER
        else:
            return Encoding.PEM


# Annoyingly, due to a mypy bug, we can't use Union[] types in
# isinstance expressions without causing false mypy errors. So we have to
# recreate the type collection as a tuple here. And no, typing.get_args doesn't
# work due to another mypy bug.
#
# mypy issues:
#  * https://github.com/python/mypy/issues/17680
#  * https://github.com/python/mypy/issues/15106
CertificateIssuerPrivateKeyTypesTpl = (
    dsa.DSAPrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
)


def make_csr(
    private_key_pem: bytes,
    domains: Optional[Union[set[str], list[str]]] = None,
    must_staple: bool = False,
    ipaddrs: Optional[list[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = None,
) -> bytes:
    """Generate a CSR containing domains or IPs as subjectAltNames.

    Parameters are ordered this way for backwards compatibility when called using positional
    arguments.

    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :param list domains: List of DNS names to include in subjectAltNames of CSR.
    :param bool must_staple: Whether to include the TLS Feature extension (aka
        OCSP Must Staple: https://tools.ietf.org/html/rfc7633).
    :param list ipaddrs: List of IPaddress(type ipaddress.IPv4Address or ipaddress.IPv6Address)
        names to include in subbjectAltNames of CSR.

    :returns: buffer PEM-encoded Certificate Signing Request.

    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, CertificateIssuerPrivateKeyTypesTpl):
        raise ValueError(f"Invalid private key type: {type(private_key)}")
    if domains is None:
        domains = []
    if ipaddrs is None:
        ipaddrs = []
    if len(domains) + len(ipaddrs) == 0:
        raise ValueError(
            "At least one of domains or ipaddrs parameter need to be not empty"
        )

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(d) for d in domains]
                + [x509.IPAddress(i) for i in ipaddrs]
            ),
            critical=False,
        )
    )
    if must_staple:
        builder = builder.add_extension(
            # "status_request" is the feature commonly known as OCSP
            # Must-Staple
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    csr = builder.sign(private_key, hashes.SHA256())
    return csr.public_bytes(Encoding.PEM)


def get_names_from_subject_and_extensions(
    subject: x509.Name, exts: x509.Extensions
) -> list[str]:
    """Gets all DNS SANs as well as the first Common Name from subject.

    :param subject: Name of the x509 object, which may include Common Name
    :type subject: `cryptography.x509.Name`
    :param exts: Extensions of the x509 object, which may include SANs
    :type exts: `cryptography.x509.Extensions`

    :returns: List of DNS Subject Alternative Names and first Common Name
    :rtype: `list` of `str`
    """
    dns_names, _ = get_identifiers_from_x509(subject, exts)
    return dns_names


def get_identifiers_from_x509(
    subject: x509.Name, exts: x509.Extensions
) -> tuple[list[str], list[str]]:
    """Gets all DNS and/or IP address SANs as well as the first Common Name from subject.

    The CN will be first in the list of DNS names, if present.

    :param subject: Name of the x509 object, which may include Common Name
    :type subject: `cryptography.x509.Name`
    :param exts: Extensions of the x509 object, which may include SANs
    :type exts: `cryptography.x509.Extensions`

    :returns: Tuple containing DNS names and IP addresses.
    """
    # We know these are always `str` because `bytes` is only possible for
    # other OIDs.
    cns = [
        typing.cast(str, c.value)
        for c in subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ]
    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        dns_names = []
        ip_addresses = []
    else:
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        ip_addresses = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]

    if not cns:
        return dns_names, ip_addresses
    else:
        # We only include the first CN, if there are multiple. This matches
        # the behavior of the previous implementation using pyOpenSSL.
        return [cns[0]] + [d for d in dns_names if d != cns[0]], ip_addresses


# Matches a complete PEM certificate block, including its footer. Counting these
# lets us detect truncated PEM blocks that x509.load_pem_x509_certificates
# silently skips.
_CERT_PEM_BLOCK_REGEX = re.compile(
    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_CERT_PEM_BEGIN_REGEX = re.compile(b"-----BEGIN CERTIFICATE-----")


def _san_identifiers(
    cert_or_req: Union[x509.Certificate, x509.CertificateSigningRequest],
) -> tuple[
    set[str],
    set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address,
              ipaddress.IPv4Network, ipaddress.IPv6Network]],
]:
    """Extract the DNS and IP identifiers from the SAN extension.

    Only the subjectAlternativeName extension is considered: the identifiers of
    an ACME order are expressed in its CSR's SANs, and comparing SAN to SAN
    avoids treating a subject Common Name as a requested identifier.

    DNS names are normalized to lowercase with a single trailing dot removed,
    and duplicate values collapse into the returned set. A leading wildcard
    label ("*.") is preserved and normalized like any other label. IP
    identifiers are returned as parsed address objects so equivalent textual
    representations compare equal.
    """
    try:
        san_ext = cert_or_req.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return set(), set()

    dns_names = {_normalize_dns_name(name)
                 for name in san_ext.value.get_values_for_type(x509.DNSName)}
    ip_identifiers = set(
        san_ext.value.get_values_for_type(x509.IPAddress))
    return dns_names, ip_identifiers


def _normalize_dns_name(name: str) -> str:
    """Normalize a DNS name for comparison: lowercase, strip one trailing dot.

    A wildcard label, if present, is kept as part of the name and only its
    remaining labels are case-normalized, matching the textual form used in
    ACME identifiers.
    """
    wildcard = name.startswith("*.")
    if wildcard:
        suffix = name[2:]
    else:
        suffix = name
    suffix = suffix.lower()
    if suffix.endswith("."):
        suffix = suffix[:-1]
    return "*." + suffix if wildcard else suffix


def _public_key_der(key: Any) -> bytes:
    return key.public_bytes(
        Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_csr_matches_cert(
    csr: x509.CertificateSigningRequest,
    cert: x509.Certificate,
) -> None:
    """Verify that an issued leaf certificate matches the requested CSR.

    The check establishes the correspondence between the issuance result and
    the order's CSR in two steps:

    1. The certificate's SubjectPublicKeyInfo must equal the CSR's, i.e. the
       same public key was certified.
    2. The DNS and IP identifiers in the certificate's subjectAlternativeName
       extension must equal those requested in the CSR's SAN extension.
       Comparison is order-independent and duplicate-insensitive; DNS names
       are case-folded with a trailing dot removed while wildcard labels are
       preserved literally, and IP addresses are compared as parsed addresses.

    :param csr: the CSR submitted when the order was created.
    :param cert: the leaf certificate returned for the finalized order.

    :raises ValueError: if the public key or the DNS/IP identifiers do not
        match.
    """
    if _public_key_der(cert.public_key()) != _public_key_der(csr.public_key()):
        raise ValueError(
            "issued leaf certificate public key does not match the order's "
            "CSR: the server returned a certificate for a different key pair")

    csr_dns, csr_ips = _san_identifiers(csr)
    cert_dns, cert_ips = _san_identifiers(cert)

    if csr_dns != cert_dns or csr_ips != cert_ips:
        missing_dns = sorted(csr_dns - cert_dns)
        unexpected_dns = sorted(cert_dns - csr_dns)
        missing_ips = sorted(str(ip) for ip in csr_ips - cert_ips)
        unexpected_ips = sorted(str(ip) for ip in cert_ips - csr_ips)
        problems = []
        if missing_dns:
            problems.append(f"missing DNS names {missing_dns}")
        if unexpected_dns:
            problems.append(f"unexpected DNS names {unexpected_dns}")
        if missing_ips:
            problems.append(f"missing IP addresses {missing_ips}")
        if unexpected_ips:
            problems.append(f"unexpected IP addresses {unexpected_ips}")
        raise ValueError(
            "issued leaf certificate identifiers do not match the order's "
            "CSR SANs: " + "; ".join(problems))


def load_fullchain_leaf(fullchain_pem: Union[str, bytes]) -> x509.Certificate:
    """Parse a fullchain PEM bundle and return its leaf certificate.

    Every PEM certificate block in the bundle must be complete and parseable:
    a truncated block or a block that cannot be decoded raises ValueError
    instead of being silently skipped, and a bundle without a leaf certificate
    raises ValueError as well.

    :param fullchain_pem: PEM-encoded certificate chain, leaf first.

    :raises ValueError: if the bundle contains no parseable complete
        certificate, or if a PEM block is truncated or otherwise invalid.
    """
    if isinstance(fullchain_pem, str):
        fullchain_bytes = fullchain_pem.encode("utf-8")
    else:
        fullchain_bytes = fullchain_pem

    block_count = len(_CERT_PEM_BLOCK_REGEX.findall(fullchain_bytes))
    begin_count = len(_CERT_PEM_BEGIN_REGEX.findall(fullchain_bytes))
    if begin_count == 0:
        raise ValueError(
            "certificate response did not contain any PEM certificate block")
    if block_count != begin_count:
        raise ValueError(
            "certificate response contained an incomplete PEM certificate "
            f"block: {begin_count} block(s) started but only {block_count} "
            "were complete and parseable")

    try:
        certs = x509.load_pem_x509_certificates(fullchain_bytes)
    except ValueError as error:
        raise ValueError(
            f"failed to parse certificate response PEM: {error}") from error
    if not certs:
        raise ValueError(
            "certificate response did not contain a parseable leaf certificate")
    return certs[0]


def _cryptography_cert_or_req_san(
    cert_or_req: Union[x509.Certificate, x509.CertificateSigningRequest],
) -> list[str]:
    """Get Subject Alternative Names from certificate or CSR using cryptography.

    .. note:: Although this is `acme` internal API, it is used by
        `letsencrypt`.

    :param cert_or_req: Certificate or CSR.
    :type cert_or_req: `x509.Certificate` or `x509.CertificateSigningRequest`.

    :returns: A list of Subject Alternative Names that is DNS.
    :rtype: `list` of `str`

    Deprecated
    .. deprecated: 3.2.1
    """
    # ???: is this translation needed?
    exts = cert_or_req.extensions
    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []

    return san_ext.value.get_values_for_type(x509.DNSName)


# Helper function that can be mocked in unit tests
def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def make_self_signed_cert(private_key: types.CertificateIssuerPrivateKeyTypes,
                          domains: Optional[list[str]] = None,
                          not_before: Optional[datetime] = None,
                          validity: Optional[timedelta] = None, force_san: bool = True,
                          extensions: Optional[list[x509.Extension]] = None,
                          ips: Optional[list[Union[ipaddress.IPv4Address,
                                                   ipaddress.IPv6Address]]] = None
                          ) -> x509.Certificate:
    """Generate new self-signed certificate.
    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :type domains: `list` of `str`
    :param int not_before: A datetime after which the cert is valid. If no
    timezone is specified, UTC is assumed
    :type not_before: `datetime.datetime`
    :param validity: Duration for which the cert will be valid. Defaults to 1
    week
    :type validity: `datetime.timedelta`
    :param buffer private_key_pem: One of
    `cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes`
    :param bool force_san:
    :param extensions: List of additional extensions to include in the cert.
    :type extensions: `list` of `x509.Extension[x509.ExtensionType]`
    :type ips: `list` of (`ipaddress.IPv4Address` or `ipaddress.IPv6Address`)
    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.
    """
    warnings.warn("make_self_signed_cert is deprecated and will be removed in "
                  "an upcoming release", DeprecationWarning)
    assert domains or ips, "Must provide one or more hostnames or IPs for the cert."

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())

    if extensions is not None:
        for ext in extensions:
            builder = builder.add_extension(ext.value, ext.critical)
    if domains is None:
        domains = []
    if ips is None:
        ips = []
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)

    name_attrs = []
    if len(domains) > 0:
        name_attrs.append(x509.NameAttribute(
            x509.OID_COMMON_NAME,
            domains[0]
        ))

    builder = builder.subject_name(x509.Name(name_attrs))
    builder = builder.issuer_name(x509.Name(name_attrs))

    sanlist: list[x509.GeneralName] = []
    for address in domains:
        sanlist.append(x509.DNSName(address))
    for ip in ips:
        sanlist.append(x509.IPAddress(ip))
    if force_san or len(domains) > 1 or len(ips) > 0:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sanlist),
            critical=False
        )

    if not_before is None:
        not_before = _now()
    if validity is None:
        validity = timedelta(seconds=7 * 24 * 60 * 60)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_before + validity)

    public_key = private_key.public_key()
    builder = builder.public_key(public_key)
    return builder.sign(private_key, hashes.SHA256())


def dump_cryptography_chain(
    chain: list[x509.Certificate],
    encoding: Encoding = Encoding.PEM,
) -> bytes:
    """Dump certificate chain into a bundle.

    :param list chain: List of `cryptography.x509.Certificate`.

    :returns: certificate chain bundle
    :rtype: bytes

    Deprecated
    .. deprecated: 3.2.1
    """
    # XXX: returns empty string when no chain is available, which
    # shuts up RenewableCert, but might not be the best solution...
    if encoding not in (Encoding.PEM, Encoding.DER):
        raise ValueError("Encoding must be PEM or DER")

    def _dump_cert(cert: x509.Certificate) -> bytes:
        return cert.public_bytes(encoding)

    # assumes that x509.Certificate.public_bytes includes ending
    # newline character
    return b"".join(_dump_cert(cert) for cert in chain)
