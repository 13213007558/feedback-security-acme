"""Tests for acme.renewal_planner using test certs, a controlled random
source, and fake ARI fetchers. No network or real CA is involved."""
import datetime
import json
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acme import renewal_planner as rp

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)


def make_cert(not_before, not_after, serial=56789, akid=b"1234",
              issuer_common_name="Some Issuer", with_aki=True):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateBuilder(
        issuer_name=x509.Name([x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, issuer_common_name)]),
        subject_name=x509.Name([]),
        public_key=key.public_key(),
        serial_number=serial,
        not_valid_before=not_before,
        not_valid_after=not_after,
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("example.com")]),
        critical=False)
    if with_aki:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(akid, None, None), critical=False)
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def valid_cert(**kwargs):
    kwargs.setdefault("not_before", datetime.datetime(2026, 1, 1, tzinfo=UTC))
    kwargs.setdefault("not_after", datetime.datetime(2026, 12, 31, tzinfo=UTC))
    return make_cert(**kwargs)


def ari_response(start, end, retry_after=None):
    return rp.ARIResponse(start, end, retry_after)


def fetcher_returning(response):
    calls = []
    def fetch(cert_pem):
        calls.append(cert_pem)
        return response
    fetch.calls = calls
    return fetch


def fetcher_raising(message="connection refused"):
    def fetch(cert_pem):
        raise rp.AriFetchError(message)
    return fetch


def never_called():
    def fetch(cert_pem):
        raise AssertionError("ARI fetcher must not be called")
    return fetch


def plan(cert_pem, response=None, state=None, policy=None, rand=lambda: 0.5,
         fetcher=None, now=NOW):
    if fetcher is None:
        fetcher = fetcher_returning(response)
    return rp.plan_renewal(now, cert_pem, state or rp.CertState(),
                           policy or rp.RenewalPolicy(), fetcher, rand)


class TestCertId:
    """Audit of the ARI certID construction in acme.client."""

    def test_same_serial_different_issuer_get_distinct_ids(self):
        from acme.client import _renewal_info_path_component
        certs = []
        for akid, issuer in ((b"aaaa", "Issuer A"), (b"bbbb", "Issuer B")):
            pem = valid_cert(serial=999, akid=akid, issuer_common_name=issuer)
            certs.append(x509.load_pem_x509_certificate(pem))
        assert certs[0].serial_number == certs[1].serial_number
        id_a = _renewal_info_path_component(certs[0])
        id_b = _renewal_info_path_component(certs[1])
        assert id_a != id_b
        # The serial half is identical; only the issuer key id differs.
        assert id_a.split(".")[1] == id_b.split(".")[1]
        assert id_a.split(".")[0] != id_b.split(".")[0]

    def test_known_vector(self):
        from acme.client import _renewal_info_path_component
        cert = x509.load_pem_x509_certificate(valid_cert())
        # base64url(b"1234") without padding; serial 56789 = 0xDDD5 encoded
        # as the signed DER INTEGER 00 DD D5.
        assert _renewal_info_path_component(cert) == "MTIzNA.AN3V"

    def test_serial_with_high_bit_gets_der_sign_byte(self):
        from acme.client import _renewal_info_path_component
        cert = x509.load_pem_x509_certificate(valid_cert(serial=0x80))
        # 0x80 must be encoded as 00 80 so it is not read as negative.
        assert _renewal_info_path_component(cert).split(".")[1] == "AIA"

    def test_missing_akid_raises_but_state_id_falls_back(self):
        from acme.client import _renewal_info_path_component
        pem = valid_cert(with_aki=False)
        cert = x509.load_pem_x509_certificate(pem)
        with pytest.raises(x509.ExtensionNotFound):
            _renewal_info_path_component(cert)
        assert rp.cert_state_id(pem).startswith("noakid-")

    def test_state_files_distinguish_same_serial_different_issuer(self):
        pem_a = valid_cert(serial=999, akid=b"aaaa")
        pem_b = valid_cert(serial=999, akid=b"bbbb")
        assert rp.cert_state_id(pem_a) != rp.cert_state_id(pem_b)


class TestExpiredAndDeadline:
    def test_expired_cert_renews_now_without_querying_ari(self):
        pem = make_cert(datetime.datetime(2026, 1, 1, tzinfo=UTC),
                        datetime.datetime(2026, 3, 1, tzinfo=UTC))
        result = plan(pem, fetcher=never_called())
        assert result.action == rp.RENEW_NOW
        assert result.renew_at == NOW
        assert any(a.code == "certificate-expired" and a.level == rp.CRITICAL
                   for a in result.alerts)

    def test_past_local_hard_deadline_renews_now(self):
        pem = valid_cert(
            not_after=NOW + datetime.timedelta(days=10))
        policy = rp.RenewalPolicy(
            renew_before_expiry=datetime.timedelta(days=30))
        result = plan(pem, fetcher=never_called(), policy=policy)
        assert result.action == rp.RENEW_NOW
        assert any(a.code == "past-local-deadline" for a in result.alerts)


class TestWindow:
    def window(self, start, end):
        return ari_response(
            start, end, retry_after=NOW + datetime.timedelta(hours=6))

    def test_before_window_waits_and_spread_stays_in_window(self):
        pem = valid_cert()
        start = NOW + datetime.timedelta(days=100)
        end = NOW + datetime.timedelta(days=200)
        for fraction in (0.0, 0.25, 0.5, 0.75, 0.999999):
            result = plan(pem, self.window(start, end),
                          rand=lambda: fraction)
            assert result.action == rp.WAIT
            assert start <= result.renew_at <= end
            expected = start + (end - start) * fraction
            assert result.renew_at == expected

    def test_window_fully_in_the_past_renews_now(self):
        pem = valid_cert()
        start = NOW - datetime.timedelta(days=10)
        end = NOW - datetime.timedelta(days=5)
        result = plan(pem, self.window(start, end))
        assert result.action == rp.RENEW_NOW
        assert result.renew_at <= NOW

    def test_server_window_never_pushes_past_local_deadline(self):
        pem = valid_cert(not_after=NOW + datetime.timedelta(days=40))
        policy = rp.RenewalPolicy(
            renew_before_expiry=datetime.timedelta(days=30))
        hard_deadline = NOW + datetime.timedelta(days=10)
        # Server suggests a window starting after the local hard deadline.
        start = NOW + datetime.timedelta(days=20)
        end = NOW + datetime.timedelta(days=30)
        result = plan(pem, self.window(start, end), policy=policy)
        assert result.renew_at == hard_deadline
        assert any(a.code == "ari-window-beyond-local-deadline"
                   for a in result.alerts)

    def test_random_spread_clamped_to_local_deadline(self):
        pem = valid_cert(not_after=NOW + datetime.timedelta(days=40))
        policy = rp.RenewalPolicy(
            renew_before_expiry=datetime.timedelta(days=30))
        hard_deadline = NOW + datetime.timedelta(days=10)
        # Window starts before the deadline but ends after it.
        start = NOW + datetime.timedelta(days=5)
        end = NOW + datetime.timedelta(days=30)
        for fraction in (0.0, 0.5, 0.999999):
            result = plan(pem, self.window(start, end), policy=policy,
                          rand=lambda: fraction)
            assert start <= result.renew_at <= hard_deadline
        # rand() == 1.0 lands exactly on the clamped end, never beyond.
        result = plan(pem, self.window(start, end), policy=policy,
                      rand=lambda: 0.999999999)
        assert result.renew_at < hard_deadline + datetime.timedelta(seconds=1)

    def test_invalid_window_is_a_fetch_failure(self):
        pem = valid_cert()
        start = NOW + datetime.timedelta(days=10)
        end = NOW + datetime.timedelta(days=5)  # end before start
        result = plan(pem, self.window(start, end))
        assert result.state.consecutive_ari_failures == 1
        assert result.state.last_error is not None


class TestTwoClocks:
    def test_retry_after_in_future_skips_fetch_and_reuses_schedule(self):
        pem = valid_cert()
        renew_at = NOW + datetime.timedelta(days=50)
        retry_after = NOW + datetime.timedelta(hours=6)
        state = rp.CertState(scheduled_renewal_time=renew_at,
                             ari_retry_after=retry_after)
        result = plan(pem, state=state, fetcher=never_called())
        assert result.action == rp.WAIT
        assert result.renew_at == renew_at
        assert result.next_ari_check == retry_after

    def test_renewal_clock_and_requery_clock_are_independent(self):
        pem = valid_cert()
        start = NOW + datetime.timedelta(days=100)
        end = NOW + datetime.timedelta(days=200)
        retry_after = NOW + datetime.timedelta(hours=1)
        result = plan(pem, ari_response(start, end, retry_after))
        # The re-query clock does not delay or trigger renewal...
        assert result.renew_at >= start
        assert result.next_ari_check == retry_after
        # ...and both are persisted separately.
        assert result.state.scheduled_renewal_time == result.renew_at
        assert result.state.ari_retry_after == retry_after

    def test_persisted_schedule_is_reclamped_after_policy_change(self):
        pem = valid_cert(not_after=NOW + datetime.timedelta(days=40))
        renew_at = NOW + datetime.timedelta(days=30)
        state = rp.CertState(scheduled_renewal_time=renew_at,
                             ari_retry_after=NOW + datetime.timedelta(hours=6))
        policy = rp.RenewalPolicy(
            renew_before_expiry=datetime.timedelta(days=30))
        result = plan(pem, state=state, policy=policy,
                      fetcher=never_called())
        assert result.renew_at == NOW + datetime.timedelta(days=10)


class TestFailure:
    def test_server_unavailable_falls_back_and_backs_off(self):
        pem = valid_cert()
        result = plan(pem, fetcher=fetcher_raising())
        assert result.action == rp.WAIT
        assert result.state.consecutive_ari_failures == 1
        assert result.next_ari_check == NOW + datetime.timedelta(hours=6)
        # Local fallback schedule: 2/3 through the lifetime.
        assert result.renew_at > NOW

    def test_backoff_doubles_and_is_capped(self):
        pem = valid_cert()
        state = rp.CertState(consecutive_ari_failures=2)
        result = plan(pem, state=state, fetcher=fetcher_raising())
        assert result.next_ari_check == NOW + datetime.timedelta(hours=24)
        state = rp.CertState(consecutive_ari_failures=10)
        result = plan(pem, state=state, fetcher=fetcher_raising())
        assert result.next_ari_check == NOW + datetime.timedelta(hours=24)

    def test_repeated_failures_raise_warning_alert(self):
        pem = valid_cert()
        state = rp.CertState(consecutive_ari_failures=2)
        result = plan(pem, state=state, fetcher=fetcher_raising())
        assert result.state.consecutive_ari_failures == 3
        assert any(a.code == "ari-unavailable" and a.level == rp.WARNING
                   for a in result.alerts)

    def test_failure_near_deadline_escalates_to_critical(self):
        pem = valid_cert(not_after=NOW + datetime.timedelta(days=35))
        policy = rp.RenewalPolicy(
            renew_before_expiry=datetime.timedelta(days=30),
            alert_lead_time=datetime.timedelta(days=7))
        state = rp.CertState(consecutive_ari_failures=2)
        result = plan(pem, state=state, policy=policy,
                      fetcher=fetcher_raising())
        assert any(a.code == "ari-down-near-deadline"
                   and a.level == rp.CRITICAL for a in result.alerts)

    def test_successful_fetch_resets_failure_count(self):
        pem = valid_cert()
        state = rp.CertState(consecutive_ari_failures=5)
        start = NOW + datetime.timedelta(days=100)
        end = NOW + datetime.timedelta(days=200)
        result = plan(pem, ari_response(start, end), state=state)
        assert result.state.consecutive_ari_failures == 0
        assert result.state.last_error is None

    def test_no_renewal_info_endpoint_uses_local_schedule(self):
        pem = valid_cert()
        result = plan(pem, response=None)
        assert result.action == rp.WAIT
        assert result.next_ari_check == NOW + datetime.timedelta(hours=6)


class TestFetchAriWindow:
    """The production adapter against a mocked acme client."""

    def make_client(self, payload=None, directory=True, get_side_effect=None):
        client = mock.Mock()
        client.directory = ({"renewalInfo": "https://ca.example/renewal-info"}
                            if directory else {})
        if get_side_effect is not None:
            client.net.get.side_effect = get_side_effect
        else:
            resp = mock.Mock()
            resp.json.return_value = payload
            client.net.get.return_value = resp
        client.retry_after.return_value = NOW + datetime.timedelta(hours=6)
        return client

    def test_missing_suggested_window_fields(self):
        client = self.make_client(payload={"suggestedWindow": {
            "start": "2026-03-20T00:00:00Z"}})
        with pytest.raises(rp.AriFetchError, match="missing suggestedWindow"):
            rp.fetch_ari_window(client, valid_cert())

    def test_missing_suggested_window_entirely(self):
        client = self.make_client(payload={})
        with pytest.raises(rp.AriFetchError):
            rp.fetch_ari_window(client, valid_cert())

    def test_server_unavailable(self):
        import requests
        client = self.make_client(
            get_side_effect=requests.ConnectionError("down"))
        with pytest.raises(rp.AriFetchError, match="failed to fetch"):
            rp.fetch_ari_window(client, valid_cert())

    def test_no_renewal_info_in_directory_returns_none(self):
        client = self.make_client(directory=False)
        assert rp.fetch_ari_window(client, valid_cert()) is None

    def test_success_returns_raw_window_and_retry_after(self):
        client = self.make_client(payload={"suggestedWindow": {
            "start": "2026-03-20T00:00:00Z", "end": "2026-03-25T00:00:00Z"}})
        response = rp.fetch_ari_window(client, valid_cert())
        assert response.window_start == datetime.datetime(
            2026, 3, 20, tzinfo=UTC)
        assert response.window_end == datetime.datetime(
            2026, 3, 25, tzinfo=UTC)
        assert response.retry_after == NOW + datetime.timedelta(hours=6)


class TestPersistence:
    def test_roundtrip(self, tmp_path):
        pem = valid_cert()
        state = rp.CertState(
            scheduled_renewal_time=NOW + datetime.timedelta(days=50),
            ari_retry_after=NOW + datetime.timedelta(hours=6),
            consecutive_ari_failures=2, last_error="boom")
        rp.save_state(str(tmp_path), pem, state)
        assert rp.load_state(str(tmp_path), pem) == state

    def test_missing_file_yields_fresh_state(self, tmp_path):
        assert rp.load_state(str(tmp_path), valid_cert()) == rp.CertState()

    def test_corrupt_file_is_discarded(self, tmp_path):
        pem = valid_cert()
        path = tmp_path / (rp.cert_state_id(pem) + ".json")
        path.write_text("{not json")
        state = rp.load_state(str(tmp_path), pem)
        assert state.scheduled_renewal_time is None
        assert "corrupt" in state.last_error

    def test_legacy_naive_datetimes_are_read_as_utc(self, tmp_path):
        pem = valid_cert()
        path = tmp_path / (rp.cert_state_id(pem) + ".json")
        path.write_text(json.dumps({
            "scheduled_renewal_time": "2026-05-04T12:00:00",
            "ari_retry_after": "2026-03-15T18:00:00",
            "consecutive_ari_failures": 0, "last_error": None}))
        state = rp.load_state(str(tmp_path), pem)
        assert state.ari_retry_after == datetime.datetime(
            2026, 3, 15, 18, tzinfo=UTC)

    def test_persisted_past_renewal_time_triggers_renewal(self, tmp_path):
        pem = valid_cert()
        state = rp.CertState(
            scheduled_renewal_time=NOW - datetime.timedelta(hours=1),
            ari_retry_after=NOW + datetime.timedelta(hours=6))
        result = plan(pem, state=state, fetcher=never_called())
        assert result.action == rp.RENEW_NOW


class TestAlert:
    def test_approaching_deadline_alerts(self):
        pem = valid_cert(not_after=NOW + datetime.timedelta(days=35))
        policy = rp.RenewalPolicy(
            renew_before_expiry=datetime.timedelta(days=30),
            alert_lead_time=datetime.timedelta(days=7))
        start = NOW + datetime.timedelta(days=1)
        end = NOW + datetime.timedelta(days=2)
        result = plan(pem, ari_response(start, end), policy=policy)
        assert any(a.code == "approaching-local-deadline"
                   and a.level == rp.WARNING for a in result.alerts)

    def test_comfortable_schedule_has_no_alerts(self):
        pem = valid_cert()
        start = NOW + datetime.timedelta(days=100)
        end = NOW + datetime.timedelta(days=200)
        result = plan(pem, ari_response(start, end))
        assert result.alerts == ()
