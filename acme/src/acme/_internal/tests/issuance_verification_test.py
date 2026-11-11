"""Tests for issuance result verification helpers in acme.crypto_util."""
import ipaddress
import unittest

from cryptography.hazmat.primitives import serialization
import pytest

from acme import crypto_util
from acme._internal.tests import test_util


class VerifyCsrMatchesCertTest(unittest.TestCase):
    """Tests for crypto_util.verify_csr_matches_cert."""

    def setUp(self):
        self.leaf_key = test_util.generate_test_key()
        self.issuer_key = test_util.generate_test_key()

    def _csr(self, dns_names=(), ip_addresses=(), key=None):
        return test_util.generate_test_csr(
            key or self.leaf_key, dns_names=dns_names,
            ip_addresses=ip_addresses)

    def _cert(self, dns_names=(), ip_addresses=(), key=None, **kwargs):
        return test_util.generate_test_cert(
            key or self.leaf_key, dns_names=dns_names,
            ip_addresses=ip_addresses, issuer_key=self.issuer_key, **kwargs)

    def test_matching_dns_and_ip_identifiers(self):
        csr = self._csr(dns_names=['example.com', 'www.example.com'],
                        ip_addresses=['192.0.2.10', '2001:db8::1'])
        cert = self._cert(dns_names=['example.com', 'www.example.com'],
                          ip_addresses=['192.0.2.10', '2001:db8::1'])
        crypto_util.verify_csr_matches_cert(csr, cert)

    def test_wrong_public_key_rejected(self):
        other_key = test_util.generate_test_key()
        csr = self._csr(dns_names=['example.com'])
        cert = self._cert(dns_names=['example.com'], key=other_key)
        with pytest.raises(ValueError, match='public key'):
            crypto_util.verify_csr_matches_cert(csr, cert)

    def test_missing_dns_name_rejected(self):
        csr = self._csr(dns_names=['example.com', 'www.example.com'])
        cert = self._cert(dns_names=['example.com'])
        with pytest.raises(ValueError, match='missing DNS names') as error:
            crypto_util.verify_csr_matches_cert(csr, cert)
        assert 'www.example.com' in str(error.value)

    def test_unexpected_dns_name_rejected(self):
        csr = self._csr(dns_names=['example.com'])
        cert = self._cert(dns_names=['example.com', 'extra.example.com'])
        with pytest.raises(ValueError, match='unexpected DNS names') as error:
            crypto_util.verify_csr_matches_cert(csr, cert)
        assert 'extra.example.com' in str(error.value)

    def test_missing_ip_rejected(self):
        csr = self._csr(ip_addresses=['192.0.2.10'])
        cert = self._cert()
        with pytest.raises(ValueError, match='missing IP addresses'):
            crypto_util.verify_csr_matches_cert(csr, cert)

    def test_unexpected_ip_rejected(self):
        csr = self._csr()
        cert = self._cert(ip_addresses=['192.0.2.10'])
        with pytest.raises(ValueError, match='unexpected IP addresses'):
            crypto_util.verify_csr_matches_cert(csr, cert)

    def test_identifier_order_does_not_matter(self):
        csr = self._csr(dns_names=['a.example.com', 'b.example.com'],
                        ip_addresses=['192.0.2.1', '192.0.2.2'])
        cert = self._cert(dns_names=['b.example.com', 'a.example.com'],
                          ip_addresses=['192.0.2.2', '192.0.2.1'])
        crypto_util.verify_csr_matches_cert(csr, cert)

    def test_duplicate_identifiers_ignored(self):
        csr = self._csr(dns_names=['example.com', 'example.com'])
        cert = self._cert(dns_names=['example.com'])
        crypto_util.verify_csr_matches_cert(csr, cert)

    def test_dns_case_and_trailing_dot_normalized(self):
        csr = self._csr(dns_names=['Example.COM.'])
        cert = self._cert(dns_names=['example.com'])
        crypto_util.verify_csr_matches_cert(csr, cert)

    def test_wildcard_preserved_literally(self):
        csr = self._csr(dns_names=['*.example.com'])
        matching_cert = self._cert(dns_names=['*.EXAMPLE.com'])
        crypto_util.verify_csr_matches_cert(csr, matching_cert)

        bare_cert = self._cert(dns_names=['example.com'])
        with pytest.raises(ValueError):
            crypto_util.verify_csr_matches_cert(csr, bare_cert)

    def test_wildcard_trailing_dot_normalized(self):
        csr = self._csr(dns_names=['*.example.com.'])
        cert = self._cert(dns_names=['*.example.com'])
        crypto_util.verify_csr_matches_cert(csr, cert)

    def test_ipv6_textual_forms_compare_equal(self):
        csr = self._csr(ip_addresses=['2001:db8::1'])
        cert = self._cert(
            ip_addresses=[str(ipaddress.IPv6Address('2001:db8:0:0:0:0:0:1'))])
        crypto_util.verify_csr_matches_cert(csr, cert)

    def test_subject_common_name_is_not_an_identifier(self):
        # Only SANs are compared; a CN on the certificate must not make a
        # certificate without the requested SANs pass.
        csr = self._csr(dns_names=['example.com'])
        cert = test_util.generate_test_cert(
            self.leaf_key, common_name='example.com',
            issuer_key=self.issuer_key)
        with pytest.raises(ValueError, match='missing DNS names'):
            crypto_util.verify_csr_matches_cert(csr, cert)

    def test_csr_without_san_requires_cert_without_san(self):
        csr = self._csr()
        cert = self._cert()
        crypto_util.verify_csr_matches_cert(csr, cert)

    def test_ec_key_pair_checked(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        ec_key = ec.generate_private_key(ec.SECP256R1())
        csr = self._csr(dns_names=['example.com'], key=ec_key)
        cert = test_util.generate_test_cert(
            ec_key, dns_names=['example.com'], issuer_key=self.issuer_key)
        crypto_util.verify_csr_matches_cert(csr, cert)


class LoadFullchainLeafTest(unittest.TestCase):
    """Tests for crypto_util.load_fullchain_leaf."""

    def setUp(self):
        self.leaf_key = test_util.generate_test_key()
        self.issuer_key = test_util.generate_test_key()
        self.leaf = test_util.generate_test_cert(
            self.leaf_key, dns_names=['example.com'],
            issuer_key=self.issuer_key)
        self.issuer = test_util.generate_test_issuer(self.issuer_key)

    def test_fullchain_returns_leaf(self):
        fullchain = test_util.cert_chain_pem([self.leaf, self.issuer])
        loaded = crypto_util.load_fullchain_leaf(fullchain)
        assert loaded.public_bytes(serialization.Encoding.DER) == \
            self.leaf.public_bytes(serialization.Encoding.DER)

    def test_leaf_only_accepted(self):
        pem = self.leaf.public_bytes(serialization.Encoding.PEM).decode()
        loaded = crypto_util.load_fullchain_leaf(pem)
        assert loaded.public_bytes(serialization.Encoding.DER) == \
            self.leaf.public_bytes(serialization.Encoding.DER)

    def test_bytes_input_accepted(self):
        fullchain = test_util.cert_chain_pem(
            [self.leaf, self.issuer]).encode()
        loaded = crypto_util.load_fullchain_leaf(fullchain)
        assert loaded.public_bytes(serialization.Encoding.DER) == \
            self.leaf.public_bytes(serialization.Encoding.DER)

    def test_without_any_pem_rejected(self):
        with pytest.raises(ValueError, match='PEM'):
            crypto_util.load_fullchain_leaf('not a certificate')

    def test_truncated_leaf_rejected(self):
        pem = self.leaf.public_bytes(serialization.Encoding.PEM)
        with pytest.raises(ValueError):
            crypto_util.load_fullchain_leaf(pem[:len(pem) // 2])

    def test_truncated_second_block_rejected(self):
        fullchain = test_util.cert_chain_pem([self.leaf, self.issuer])
        truncated = fullchain + '-----BEGIN CERTIFICATE-----\nMIIBog==\n'
        with pytest.raises(ValueError, match='incomplete PEM'):
            crypto_util.load_fullchain_leaf(truncated)

    def test_empty_input_rejected(self):
        with pytest.raises(ValueError):
            crypto_util.load_fullchain_leaf('')
