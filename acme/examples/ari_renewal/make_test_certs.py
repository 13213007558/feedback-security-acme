"""Generate local test certificates and a matching ARI fixture.

Everything is self-signed and computed relative to the generation time, so
the drill can be run at any moment without touching a real CA or the
network. Run from this directory:

    python make_test_certs.py
    python -m acme.renewal_planner --config certs.ini \
        --fixture ari_fixture.json --state-dir state
"""
import datetime
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC).replace(microsecond=0)
DAY = datetime.timedelta(days=1)


def make_cert(path, not_before, not_after, serial, akid):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = x509.CertificateBuilder(
        issuer_name=x509.Name([x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, "Demo Issuer")]),
        subject_name=x509.Name([]),
        public_key=key.public_key(),
        serial_number=serial,
        not_valid_before=not_before,
        not_valid_after=not_after,
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("example.com")]),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier(akid, None, None), critical=False,
    ).sign(private_key=key, algorithm=hashes.SHA256())
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def main():
    os.makedirs("certs", exist_ok=True)
    certs = {
        # Normal cert: server window applies as-is.
        "alpha": dict(not_before=NOW - 30 * DAY, not_after=NOW + 120 * DAY,
                      serial=1001, akid=b"demo-issuer-key-alpha"),
        # Same serial as alpha but a different issuer key id: the ARI
        # certID (and therefore the state file) must differ.
        "epsilon": dict(not_before=NOW - 30 * DAY, not_after=NOW + 90 * DAY,
                        serial=1001, akid=b"demo-issuer-key-epsilon"),
        # Expires in 35 days: local deadline (30 days before expiry) beats
        # the server-suggested window.
        "beta": dict(not_before=NOW - 60 * DAY, not_after=NOW + 35 * DAY,
                     serial=1002, akid=b"demo-issuer-key-beta"),
        # Already expired: must renew immediately without querying ARI.
        "gamma": dict(not_before=NOW - 90 * DAY, not_after=NOW - 1 * DAY,
                      serial=1003, akid=b"demo-issuer-key-gamma"),
        # Server unavailable for this one.
        "delta": dict(not_before=NOW - 30 * DAY, not_after=NOW + 90 * DAY,
                      serial=1004, akid=b"demo-issuer-key-delta"),
    }
    for name, kwargs in certs.items():
        make_cert(os.path.join("certs", name + ".pem"), **kwargs)

    # certID = base64url(AKID).base64url(DER serial); computed here via the
    # same code path the planner uses.
    from acme.renewal_planner import cert_state_id
    cert_ids = {}
    for name in certs:
        with open(os.path.join("certs", name + ".pem"), "rb") as f:
            cert_ids[name] = cert_state_id(f.read())

    fixture = {
        "renewal_info_available": True,
        "responses": {
            cert_ids["alpha"]: {
                "window_start": iso(NOW + 60 * DAY),
                "window_end": iso(NOW + 70 * DAY),
                "retry_after_seconds": 21600,
            },
            # Window entirely in the past: renew immediately.
            cert_ids["epsilon"]: {
                "window_start": iso(NOW - 10 * DAY),
                "window_end": iso(NOW - 5 * DAY),
                "retry_after_seconds": 21600,
            },
            # Window beyond the local hard deadline: gets clamped.
            cert_ids["beta"]: {
                "window_start": iso(NOW + 20 * DAY),
                "window_end": iso(NOW + 30 * DAY),
                "retry_after_seconds": 21600,
            },
            # gamma has no entry on purpose: the planner must not query
            # ARI for an expired certificate.
            cert_ids["delta"]: {"error": "HTTP 503: service unavailable"},
        },
    }
    with open("ari_fixture.json", "w") as f:
        json.dump(fixture, f, indent=2)
        f.write("\n")

    print("wrote certs/ and ari_fixture.json")
    for name, cert_id in cert_ids.items():
        print(f"  {name:8s} certID {cert_id}")


if __name__ == "__main__":
    main()
