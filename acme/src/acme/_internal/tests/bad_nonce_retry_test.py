"""Signature-level regression tests for ACME ``badNonce`` retry behavior.

These tests exercise three real entry points of the ACME v2 client:

* ``ClientV2.new_account`` (a ``newAccount`` request authenticated with a
  ``jwk`` and no ``kid``),
* ``ClientV2._post_as_get`` (an existing-account POST-as-GET request
  authenticated with a ``kid`` and an empty-string payload), and
* ``ClientV2.begin_finalization`` (a ``finalize`` request authenticated with a
  ``kid`` carrying the CSR as payload).

A stateful fake ACME server is mounted at the transport layer
(``requests.Session.request``). It hands out nonces from a ``newNonce``
endpoint, records every raw ``application/jose+json`` body it receives and
independently verifies each JWS. The tests therefore prove that a retry after
``badNonce`` produces a brand new, legitimately signed JWS consuming a fresh
nonce rather than resending an old signature or an old nonce.
"""

import base64
import http.client as http_client
import json
from unittest import mock

import josepy as jose
import pytest
import requests

from acme import errors
from acme import jws as acme_jws
from acme import messages
from acme._internal.tests import test_util
from acme.client import ClientNetwork
from acme.client import ClientV2

KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))
PUBLIC_KEY = KEY.public_key()
CSR_PEM = test_util.load_vector("csr-mixed.pem")

BASE_URL = "https://acme.test.example/acme"
NEW_NONCE_URL = BASE_URL + "/new-nonce"
NEW_ACCOUNT_URL = BASE_URL + "/new-account"
AUTHZ_URL = BASE_URL + "/authz/1"
FINALIZE_URL = BASE_URL + "/order/1/finalize"
ACCOUNT_URL = BASE_URL + "/acct/1"

# A Replay-Nonce header value that cannot be decoded as JOSE base64. The
# embedded space makes base64url decoding raise DeserializationError, which is
# what ClientNetwork._add_nonce turns into acme.errors.BadNonce.
UNDECODABLE_NONCE = "not a valid nonce!!"

DIRECTORY = messages.Directory(
    {
        "newAccount": NEW_ACCOUNT_URL,
        "newNonce": NEW_NONCE_URL,
        "newOrder": BASE_URL + "/new-order",
        "revokeCert": BASE_URL + "/revoke-cert",
        "meta": messages.Directory.Meta(),
    }
)


class RecordedRequest:
    """A single request observed by the fake ACME server."""

    def __init__(self, method, url, raw_jws=None):
        self.method = method
        self.url = url
        # raw_jws is the exact application/jose+json bytes put on the wire
        self.raw_jws = raw_jws
        self.jws = acme_jws.JWS.json_loads(raw_jws) if raw_jws is not None else None


class FakeACMEServer:
    """Stateful ACME server stand-in mounted at ``Session.request``.

    :param bad_nonce_responses: number of initial POST attempts that must be
        answered with an ACME ``badNonce`` problem document before a normal
        response is returned.
    :param poisoned_bad_nonce: if True, ``badNonce`` responses also carry a
        Replay-Nonce header that is not valid base64url. A conforming client
        must ignore it and fetch a replacement nonce from newNonce instead.
    :param undecodable_success_nonce: if True, the first successful POST
        response carries a Replay-Nonce header that cannot be decoded.
    :param failure: optional ``('network', exc)`` or ``(status, acme_code)``
        tuple describing a non-badNonce failure to return on every POST.
    :param undecodable_head_nonce: if True, the first newNonce HEAD response
        carries a Replay-Nonce header that cannot be decoded.
    :param missing_success_nonce: if True, the first successful POST response
        carries no Replay-Nonce header at all.
    """

    def __init__(
        self,
        bad_nonce_responses=0,
        poisoned_bad_nonce=False,
        undecodable_success_nonce=False,
        failure=None,
        undecodable_head_nonce=False,
        missing_success_nonce=False,
    ):
        self.key = PUBLIC_KEY
        self.account_url = ACCOUNT_URL
        self.requests = []
        self.issued_nonces = set()
        # Nonces the server accepted (i.e. that actually executed the request).
        self.consumed_nonces = set()
        # Every nonce that appeared in a signed POST, accepted or rejected.
        self.observed_nonces = []
        self.bad_nonce_responses = bad_nonce_responses
        self.poisoned_bad_nonce = poisoned_bad_nonce
        self.undecodable_success_nonce = undecodable_success_nonce
        self.undecodable_head_nonce = undecodable_head_nonce
        self.missing_success_nonce = missing_success_nonce
        self.failure = failure
        self._nonce_counter = 0
        self._bad_nonces_served = 0
        self._head_responses = 0
        self._success_posts = 0

    def __call__(self, _session, method, url, *args, **kwargs):
        if method == "HEAD":
            self.requests.append(RecordedRequest("HEAD", url))
            return self._head_response(url)
        assert method == "POST"
        raw_jws = kwargs["data"].encode() if isinstance(kwargs["data"], str) else kwargs["data"]
        recorded = RecordedRequest("POST", url, raw_jws)
        self.requests.append(recorded)
        # The signature and protected URL are verified for every request on
        # the wire, including ones the server answers with badNonce.
        self._verify_signature(recorded)
        nonce = recorded.jws.signature.combined.nonce.decode()
        assert nonce in self.issued_nonces, "JWS used a nonce the server never issued"
        assert nonce not in self.observed_nonces, "JWS reused a nonce seen on an earlier POST"
        self.observed_nonces.append(nonce)
        # A badNonce answer means the server rejected the nonce, so the
        # accepted-nonce bookkeeping is only meaningful on successful attempts.
        will_reject = self.failure is None and self._bad_nonces_served < self.bad_nonce_responses
        if not will_reject:
            self._check_nonce(recorded)
        return self._post_response(recorded)

    def _fresh_nonce(self):
        self._nonce_counter += 1
        decoded_nonce = f"nonce-{self._nonce_counter}".encode()
        # Nonces are tracked in their decoded form, which is how a consumed
        # nonce appears inside a signed JWS protected header.
        self.issued_nonces.add(decoded_nonce.decode())
        return jose.b64encode(decoded_nonce).decode()

    def _head_response(self, url):
        self._head_responses += 1
        response = requests.Response()
        response.url = url
        response.status_code = http_client.OK
        if self.undecodable_head_nonce and self._head_responses == 1:
            response.headers[ClientNetwork.REPLAY_NONCE_HEADER] = UNDECODABLE_NONCE
        else:
            response.headers[ClientNetwork.REPLAY_NONCE_HEADER] = self._fresh_nonce()
        response.headers["Content-Type"] = ClientNetwork.JSON_CONTENT_TYPE
        return response

    def _verify_signature(self, recorded):
        """Independently validate the signature and protected URL."""
        parsed = recorded.jws
        # The signature must actually verify against the account public key.
        assert parsed.verify(self.key), "JWS signature failed verification"
        # The protected URL must be the exact URL the request was POSTed to.
        assert parsed.signature.combined.url == recorded.url

    def _check_nonce(self, recorded):
        """Validate nonce provenance and single use against server state."""
        nonce = recorded.jws.signature.combined.nonce.decode()
        assert nonce in self.issued_nonces, "JWS used a nonce the server never issued"
        assert nonce not in self.consumed_nonces, "JWS reused a previously consumed nonce"
        self.consumed_nonces.add(nonce)

    def _post_response(self, recorded):
        if self.failure is not None:
            return self._failure_response(recorded.url)

        if self._bad_nonces_served < self.bad_nonce_responses:
            self._bad_nonces_served += 1
            return self._bad_nonce_response(recorded.url)

        self._success_posts += 1
        return self._success_response(recorded)

    def _bad_nonce_response(self, url):
        response = requests.Response()
        response.url = url
        response.status_code = http_client.BAD_REQUEST
        response.headers["Content-Type"] = ClientNetwork.JSON_ERROR_CONTENT_TYPE
        if self.poisoned_bad_nonce:
            # A value the client must not try to use on the retry.
            response.headers[ClientNetwork.REPLAY_NONCE_HEADER] = UNDECODABLE_NONCE
        body = messages.Error.with_code("badNonce", detail="the nonce you sent is stale or unknown")
        response._content = body.json_dumps().encode()
        return response

    def _failure_response(self, url):
        kind, value = self.failure
        if kind == "network":
            raise value
        response = requests.Response()
        response.url = url
        response.status_code = kind
        response.headers["Content-Type"] = ClientNetwork.JSON_ERROR_CONTENT_TYPE
        body = messages.Error.with_code(value)
        response._content = body.json_dumps().encode()
        return response

    def _success_response(self, recorded):
        response = requests.Response()
        response.url = recorded.url
        response.status_code = (
            http_client.CREATED if recorded.url == NEW_ACCOUNT_URL else http_client.OK
        )
        if self.missing_success_nonce and self._success_posts == 1:
            # A 2xx POST with no Replay-Nonce header violates RFC 8555.
            pass
        elif self.undecodable_success_nonce and self._success_posts == 1:
            response.headers[ClientNetwork.REPLAY_NONCE_HEADER] = UNDECODABLE_NONCE
        else:
            response.headers[ClientNetwork.REPLAY_NONCE_HEADER] = self._fresh_nonce()
        response.headers["Content-Type"] = ClientNetwork.JSON_CONTENT_TYPE
        if recorded.url == NEW_ACCOUNT_URL:
            response.headers["Location"] = ACCOUNT_URL
        response._content = self._success_body(recorded)
        return response

    def _success_body(self, recorded):
        if recorded.url == NEW_ACCOUNT_URL:
            body = messages.Registration(
                contact=("mailto:admin@example.com",), status=messages.STATUS_VALID
            )
        elif recorded.url == AUTHZ_URL:
            body = messages.Authorization(
                identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com"),
                status=messages.STATUS_VALID,
            )
        else:
            body = messages.Order(status=messages.STATUS_PROCESSING)
        return body.json_dumps().encode()

    @property
    def post_requests(self):
        return [request for request in self.requests if request.method == "POST"]

    @property
    def head_requests(self):
        return [request for request in self.requests if request.method == "HEAD"]


def make_client_and_server(**server_kwargs):
    """Build a real ClientV2 wired to a fresh fake ACME server."""
    server = FakeACMEServer(**server_kwargs)
    network = ClientNetwork(
        key=KEY, alg=jose.RS256, verify_ssl=False, user_agent="acme-python-bad-nonce-test"
    )
    client = ClientV2(DIRECTORY, network)
    original_request = network.session.request

    def transport(method, url, *args, **kwargs):
        return server(original_request, method, url, *args, **kwargs)

    mocked = mock.MagicMock(side_effect=transport)
    network.session.request = mocked
    return client, network, server, mocked


def new_account_payload():
    return messages.NewRegistration.from_data(
        email="admin@example.com", terms_of_service_agreed=True
    )


def finalize_payload():
    from cryptography import x509

    csr = x509.load_pem_x509_csr(CSR_PEM)
    return messages.CertificateRequest(csr=csr)


def assert_protected_header(recorded, expected_url, expect_kid):
    """Assert alg/url and the mutually exclusive kid/jwk selection."""
    header = recorded.jws.signature.combined
    assert header.alg == jose.RS256
    assert header.url == expected_url
    if expect_kid:
        assert header.kid == ACCOUNT_URL
        assert header.jwk is None or not header.jwk.not_omitted()
    else:
        assert header.kid is None
        assert header.jwk == PUBLIC_KEY


def assert_distinct_signatures(recorded_requests):
    """No two wire requests may carry the same JWS or the same signature."""
    raw_bodies = [request.raw_jws for request in recorded_requests]
    signatures = [request.jws.signature.signature for request in recorded_requests]
    assert len(set(raw_bodies)) == len(raw_bodies)
    assert len(set(signatures)) == len(signatures)


def assert_nonces_linear(recorded_requests, server):
    """Each JWS uses a distinct, freshly issued nonce, in issue order."""
    used_nonces = [request.jws.signature.combined.nonce.decode() for request in recorded_requests]
    assert len(set(used_nonces)) == len(used_nonces)
    for nonce in used_nonces:
        assert nonce in server.issued_nonces
        assert nonce != UNDECODABLE_NONCE


class BadNonceRetryTestBase:
    """Common assertions shared by the three real entry points."""

    entry_url: str
    expect_kid: bool

    def invoke(self, client):
        raise NotImplementedError

    def assert_payload(self, recorded):
        raise NotImplementedError

    def _client_with_account(self, client):
        if self.expect_kid:
            client.net.account = messages.RegistrationResource(
                body=messages.Registration(), uri=ACCOUNT_URL
            )
        # jwk-authenticated entries (newAccount) must keep account unset, since
        # setting it would switch _wrap_in_jws to kid authentication.
        return client

    def test_success_single_request(self):
        client, _network, server, transport = make_client_and_server()
        self._client_with_account(client)

        self.invoke(client)

        # One newNonce HEAD and one POST: nothing is retried on a clean path.
        assert transport.call_count == 2
        assert len(server.head_requests) == 1
        assert len(server.post_requests) == 1
        recorded = server.post_requests[0]
        self.assert_payload(recorded)
        assert_protected_header(recorded, self.entry_url, self.expect_kid)
        assert recorded.jws.verify(PUBLIC_KEY)

    def test_bad_nonce_retries_with_fresh_jws(self):
        # One badNonce answer followed by success: the canonical retry path.
        client, _network, server, transport = make_client_and_server(bad_nonce_responses=1)
        self._client_with_account(client)

        self.invoke(client)

        # Each attempt is one POST preceded by one newNonce HEAD.
        assert transport.call_count == 4
        assert len(server.post_requests) == 2
        assert len(server.head_requests) == 2

        for recorded in server.post_requests:
            self.assert_payload(recorded)
            assert_protected_header(recorded, self.entry_url, self.expect_kid)
            assert recorded.jws.verify(PUBLIC_KEY)
            # Even the rejected attempt must carry a nonce the newNonce
            # endpoint issued rather than a fabricated or replayed value.
            assert recorded.jws.signature.combined.nonce.decode() in server.issued_nonces

        # The retry must be a new signature over a new nonce, never a replay.
        assert_distinct_signatures(server.post_requests)
        assert_nonces_linear(server.post_requests, server)
        # Every POST, rejected or accepted, used a distinct issued nonce.
        used_nonces = [
            request.jws.signature.combined.nonce.decode() for request in server.post_requests
        ]
        assert server.observed_nonces == used_nonces
        assert len(set(used_nonces)) == 2
        # Only the final successful attempt is in the accepted-nonce set.
        assert server.consumed_nonces == {used_nonces[-1]}

    def test_consecutive_bad_nonce_terminates_after_one_retry(self):
        # The client retries at most once. A second consecutive badNonce is a
        # terminal state: the badNonce error must propagate and the total
        # number of requests must stay bounded at two POSTs (plus the two
        # newNonce HEADs that provisioned their nonces).
        client, _network, server, transport = make_client_and_server(bad_nonce_responses=2)
        self._client_with_account(client)

        with pytest.raises(messages.Error) as exc_info:
            self.invoke(client)
        assert exc_info.value.code == "badNonce"

        assert transport.call_count == 4
        assert len(server.post_requests) == 2
        assert len(server.head_requests) == 2
        for recorded in server.post_requests:
            self.assert_payload(recorded)
            assert_protected_header(recorded, self.entry_url, self.expect_kid)
            assert recorded.jws.verify(PUBLIC_KEY)
        assert_distinct_signatures(server.post_requests)
        assert_nonces_linear(server.post_requests, server)
        # Nothing was ever accepted, so no nonce enters the accepted set.
        assert server.consumed_nonces == set()

    def test_bad_nonce_with_poisoned_replay_nonce_header(self):
        client, _network, server, transport = make_client_and_server(
            bad_nonce_responses=1, poisoned_bad_nonce=True
        )
        self._client_with_account(client)

        self.invoke(client)

        # The undecodable header on the error response must be discarded: the
        # client obtains the replacement nonce from a second newNonce HEAD.
        assert transport.call_count == 4
        assert len(server.head_requests) == 2
        assert len(server.post_requests) == 2
        assert_distinct_signatures(server.post_requests)
        assert_nonces_linear(server.post_requests, server)
        for recorded in server.post_requests:
            assert recorded.jws.verify(PUBLIC_KEY)

    def test_undecodable_success_nonce_is_not_retried(self):
        # An undecodable Replay-Nonce on a *successful* response is a client
        # side BadNonce raised while storing the next nonce. It must not be
        # mistaken for a server-confirmed unexecuted request and retried.
        client, _network, server, transport = make_client_and_server(undecodable_success_nonce=True)
        self._client_with_account(client)

        with pytest.raises(errors.BadNonce):
            self.invoke(client)

        assert transport.call_count == 2
        assert len(server.post_requests) == 1
        assert len(server.head_requests) == 1

    def test_undecodable_initial_head_nonce_aborts_before_post(self):
        # If even the first newNonce response is unusable, no signed POST may
        # hit the wire at all.
        client, _network, server, transport = make_client_and_server(undecodable_head_nonce=True)
        self._client_with_account(client)

        with pytest.raises(errors.BadNonce):
            self.invoke(client)

        assert transport.call_count == 1
        assert len(server.head_requests) == 1
        assert server.post_requests == []

    def test_missing_success_nonce_is_not_retried(self):
        # A successful POST that omits Replay-Nonce is a MissingNonce error
        # raised while storing the next nonce. The request did execute, so the
        # badNonce retry logic must not fire it a second time.
        client, _network, server, transport = make_client_and_server(missing_success_nonce=True)
        self._client_with_account(client)

        with pytest.raises(errors.MissingNonce):
            self.invoke(client)

        assert transport.call_count == 2
        assert len(server.post_requests) == 1
        assert len(server.head_requests) == 1
        assert server.post_requests[0].jws.verify(PUBLIC_KEY)

    @pytest.mark.parametrize(
        "failure, expected_error",
        [
            (
                ("network", requests.exceptions.ConnectionError("connection reset")),
                requests.exceptions.ConnectionError,
            ),
            ((http_client.SERVICE_UNAVAILABLE, "serverInternal"), messages.Error),
            ((http_client.BAD_REQUEST, "malformed"), messages.Error),
        ],
    )
    def test_other_failures_are_not_retried(self, failure, expected_error):
        client, _network, server, transport = make_client_and_server(failure=failure)
        self._client_with_account(client)

        with pytest.raises(expected_error):
            self.invoke(client)

        # Exactly one POST attempt: the badNonce retry path must not fire.
        assert transport.call_count == 2
        assert len(server.post_requests) == 1
        assert len(server.head_requests) == 1
        recorded = server.post_requests[0]
        assert recorded.jws.verify(PUBLIC_KEY)

    def test_tampered_retry_signature_is_detected(self):
        # Negative control: the independent verifier really rejects a forged
        # JWS rather than rubber-stamping whatever the client sends.
        client, _network, server, transport = make_client_and_server(bad_nonce_responses=1)
        self._client_with_account(client)
        self.invoke(client)

        raw = json.loads(server.post_requests[1].raw_jws)
        original_signature = raw["signature"]
        replacement = "A" if original_signature[0] != "A" else "B"
        raw["signature"] = replacement + original_signature[1:]
        tampered = acme_jws.JWS.json_loads(json.dumps(raw).encode())
        assert tampered.verify(PUBLIC_KEY) is False


class TestNewAccountBadNonce(BadNonceRetryTestBase):
    """newAccount: jwk-authenticated, no kid, registration body as payload."""

    entry_url = NEW_ACCOUNT_URL
    expect_kid = False

    def invoke(self, client):
        regr = client.new_account(new_account_payload())
        assert regr.uri == ACCOUNT_URL

    def assert_payload(self, recorded):
        expected = new_account_payload().json_dumps(indent=2).encode()
        assert recorded.jws.payload == expected
        # A newAccount request must never be a POST-as-GET empty payload.
        assert recorded.jws.payload != b""
        assert recorded.jws.payload != b"{}"


class TestPostAsGetBadNonce(BadNonceRetryTestBase):
    """Existing-account POST-as-GET: kid-authenticated with empty payload."""

    entry_url = AUTHZ_URL
    expect_kid = True

    def invoke(self, client):
        response = client._post_as_get(AUTHZ_URL)
        assert response.status_code == http_client.OK

    def assert_payload(self, recorded):
        # RFC 8555 section 6.2: POST-as-GET carries an empty-string payload,
        # which is wire-encoded as an empty payload field, not "{}".
        assert recorded.jws.payload == b""
        raw = json.loads(recorded.raw_jws)
        assert raw["payload"] == ""

    def test_empty_object_payload_is_distinct_from_post_as_get(self):
        # Sending an explicit "{}" object must serialize differently from a
        # POST-as-GET, proving the two are not conflated by the retry logic.
        client, _network, server, transport = make_client_and_server()
        client.net.account = messages.RegistrationResource(
            body=messages.Registration(), uri=ACCOUNT_URL
        )

        class EmptyObject(jose.JSONDeSerializable):
            def to_partial_json(self):
                return {}

            @classmethod
            def from_json(cls, jobj):
                return cls()

        client._post(AUTHZ_URL, EmptyObject())

        post_as_get = server.post_requests[0]
        assert post_as_get.jws.payload == b"{}"
        assert (
            json.loads(post_as_get.raw_jws)["payload"]
            == base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode()
        )
        # And the POST-as-GET encoding remains the empty string, not "e30".
        assert json.loads(post_as_get.raw_jws)["payload"] != ""


class TestFinalizeBadNonce(BadNonceRetryTestBase):
    """finalize: kid-authenticated with the CSR as payload."""

    entry_url = FINALIZE_URL
    expect_kid = True

    def invoke(self, client):
        order = messages.Order(status=messages.STATUS_PENDING, finalize=FINALIZE_URL)
        orderr = messages.OrderResource(
            body=order, uri=BASE_URL + "/order/1", authorizations=[], csr_pem=CSR_PEM
        )
        updated = client.begin_finalization(orderr)
        assert updated.body.status == messages.STATUS_PROCESSING

    def assert_payload(self, recorded):
        expected = finalize_payload().json_dumps(indent=2).encode()
        assert recorded.jws.payload == expected
        assert b"csr" in expected
