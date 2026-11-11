"""Tests for RFC 8555 keyChange (account key rollover)."""
import http.client as http_client
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
import pytest
import requests

from acme import client
from acme import errors
from acme import jws as acme_jws
from acme import messages
from acme._internal.tests import test_util

KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))
ACCOUNT_URL = 'https://example.invalid/acme/acct/1'
KEY_CHANGE_URL = 'https://example.invalid/acme/key-change'
NEW_NONCE_URL = 'https://example.invalid/acme/new-nonce'


def _fresh_key() -> jose.JWKRSA:
    return jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537, key_size=2048))


class KeyChangeMessageTest(unittest.TestCase):
    """Tests for messages.KeyChange and the inner JWS."""

    def setUp(self):
        self.new_key = _fresh_key()
        self.payload = messages.KeyChange(account=ACCOUNT_URL,
                                          oldKey=KEY.public_key())

    def test_round_trip(self):
        loaded = messages.KeyChange.json_loads(self.payload.json_dumps())
        assert loaded == self.payload
        assert loaded.account == ACCOUNT_URL
        assert loaded.oldKey == KEY.public_key()

    def test_inner_jws_structure_and_signature(self):
        inner = self.payload.sign_inner_jws(self.new_key, KEY_CHANGE_URL)
        compact = inner.to_compact()
        # Compact JWS has exactly three dot-separated parts.
        assert len(compact.split(b'.')) == 3

        reparsed = acme_jws.JWS.from_compact(compact)
        combined = reparsed.signature.combined
        # The inner JWS is signed by, and carries, the NEW public key.
        assert combined.jwk == self.new_key.public_key()
        assert reparsed.verify(self.new_key.public_key())
        # It must not carry a kid, and the url is the keyChange URL.
        assert combined.kid is None
        assert combined.url == KEY_CHANGE_URL

        inner_payload = messages.KeyChange.json_loads(reparsed.payload)
        assert inner_payload.account == ACCOUNT_URL
        assert inner_payload.oldKey == KEY.public_key()

    def test_inner_jws_rejects_old_key_signature(self):
        inner = self.payload.sign_inner_jws(self.new_key, KEY_CHANGE_URL)
        # The old key must not verify the inner signature.
        assert not inner.verify(KEY.public_key())


class KeyChangeClientTest(unittest.TestCase):
    """Tests for ClientV2.key_change state handling."""

    def setUp(self):
        self.old_key = KEY
        self.new_key = _fresh_key()
        self.directory = messages.Directory({
            'newNonce': NEW_NONCE_URL,
            'newAccount': 'https://example.invalid/acme/new-account',
            'newOrder': 'https://example.invalid/acme/new-order',
            'keyChange': KEY_CHANGE_URL,
            'meta': messages.Directory.Meta(),
        })
        self.account = messages.RegistrationResource(
            body=messages.Registration(status=messages.STATUS_VALID),
            uri=ACCOUNT_URL)
        self.net = mock.MagicMock(spec=client.ClientNetwork)
        self.net.key = self.old_key
        self.net.account = self.account
        self.net.alg = jose.RS256
        self.cli = client.ClientV2(self.directory, self.net)

        self.response = mock.MagicMock(
            ok=True, status_code=http_client.OK, links={}, headers={})
        self.response.json.return_value = self.account.body.to_json()
        self.response.headers = {'Location': ACCOUNT_URL}

    def test_success_switches_local_identity(self):
        self.net.post.return_value = self.response
        self.cli.key_change(self.new_key)

        # The network key and account are switched to the new identity.
        assert self.net.key == self.new_key
        assert self.net.account.uri == ACCOUNT_URL
        self.net.post.assert_called_once()

    def test_request_has_two_jws_layers(self):
        # Use a real ClientNetwork so the outer JWS is genuinely signed.
        real_net = client.ClientNetwork(self.old_key, account=self.account)
        real_net._get_nonce = mock.Mock(return_value=b'nonce')  # pylint: disable=protected-access
        real_net._send_request = mock.Mock(return_value=self.response)  # pylint: disable=protected-access
        real_net._check_response = mock.Mock(return_value=self.response)  # pylint: disable=protected-access
        real_net._add_nonce = mock.Mock()  # pylint: disable=protected-access
        cli = client.ClientV2(self.directory, real_net)

        cli.key_change(self.new_key)

        sent = real_net._send_request.call_args.kwargs['data']  # pylint: disable=protected-access
        outer = acme_jws.JWS.json_loads(sent)
        # Outer JWS is signed by the OLD key with the account kid.
        assert outer.signature.combined.kid == ACCOUNT_URL
        assert outer.signature.combined.url == KEY_CHANGE_URL
        assert outer.verify(self.old_key.public_key())
        assert not outer.verify(self.new_key.public_key())

        # Outer payload is the compact inner JWS.
        inner = acme_jws.JWS.from_compact(outer.payload)
        assert inner.signature.combined.jwk == self.new_key.public_key()
        assert inner.signature.combined.kid is None
        assert inner.verify(self.new_key.public_key())
        key_change = messages.KeyChange.json_loads(inner.payload)
        assert key_change.account == ACCOUNT_URL
        assert key_change.oldKey == self.old_key.public_key()

        assert real_net.key == self.new_key

    def test_definitive_server_error_keeps_old_identity(self):
        server_error = messages.Error.with_code('malformed', detail='bad oldKey')
        self.net.post.side_effect = server_error
        with pytest.raises(messages.Error):
            self.cli.key_change(self.new_key)
        # Nothing local was touched.
        assert self.net.key == self.old_key
        assert self.net.account == self.account
        # The account object is never reassigned on failure.
        self.net.post.assert_called_once()

    def test_bad_nonce_is_retried_then_succeeds(self):
        # The badNonce retry happens inside ClientNetwork.post, so exercise
        # the real network path with only the low-level send mocked.
        real_net = client.ClientNetwork(self.old_key, account=self.account)
        real_net._get_nonce = mock.Mock(return_value=b'nonce')  # pylint: disable=protected-access
        real_net._add_nonce = mock.Mock()  # pylint: disable=protected-access
        bad_response = mock.MagicMock(ok=False, status_code=400, headers={},
                                      links={})
        bad_response.json.return_value = messages.Error.with_code(
            'badNonce').to_json()
        real_net._send_request = mock.Mock(  # pylint: disable=protected-access
            side_effect=[bad_response, self.response])
        real_net._check_response = (  # pylint: disable=protected-access
            lambda response, content_type=None:
            client.ClientNetwork._check_response(response, content_type))
        cli = client.ClientV2(self.directory, real_net)

        cli.key_change(self.new_key)
        assert real_net._send_request.call_count == 2  # pylint: disable=protected-access
        assert real_net.key == self.new_key

    def test_bad_nonce_retry_exhausted_keeps_old_identity(self):
        real_net = client.ClientNetwork(self.old_key, account=self.account)
        real_net._get_nonce = mock.Mock(return_value=b'nonce')  # pylint: disable=protected-access
        real_net._add_nonce = mock.Mock()  # pylint: disable=protected-access
        bad_response = mock.MagicMock(ok=False, status_code=400, headers={},
                                      links={})
        bad_response.json.return_value = messages.Error.with_code(
            'badNonce').to_json()
        real_net._send_request = mock.Mock(return_value=bad_response)  # pylint: disable=protected-access
        real_net._check_response = (  # pylint: disable=protected-access
            lambda response, content_type=None:
            client.ClientNetwork._check_response(response, content_type))
        cli = client.ClientV2(self.directory, real_net)

        with pytest.raises(messages.Error):
            cli.key_change(self.new_key)
        assert real_net.key == self.old_key
        # One initial attempt plus the single permitted retry.
        assert real_net._send_request.call_count == 2  # pylint: disable=protected-access

    def test_transport_failure_is_uncertain_and_not_retried(self):
        transport_error = requests.exceptions.ConnectionError('reset')
        self.net.post.side_effect = transport_error
        with pytest.raises(errors.KeyChangeUncertainError) as exc_info:
            self.cli.key_change(self.new_key)
        assert exc_info.value.__cause__ is transport_error
        # Exactly one attempt: the request is never blindly replayed.
        self.net.post.assert_called_once()
        # Local identity is provably untouched.
        assert self.net.key == self.old_key
        assert self.net.account == self.account
        assert exc_info.value.account_url == ACCOUNT_URL
        assert exc_info.value.old_key == self.old_key
        assert exc_info.value.new_key == self.new_key

    def test_local_account_switch_failure_raises_local_switch_error(self):
        self.net.post.return_value = self.response
        # Simulate the local account assignment failing after server approval.
        type(self.net).account = mock.PropertyMock(
            side_effect=[self.account, RuntimeError('local store failure')])
        with pytest.raises(errors.KeyChangeLocalSwitchError) as exc_info:
            self.cli.key_change(self.new_key)
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        # The key was switched before the account assignment failed.
        assert exc_info.value.local_key_switched is True

    def test_same_key_rejected_before_request(self):
        with pytest.raises(ValueError):
            self.cli.key_change(self.old_key)
        self.net.post.assert_not_called()

    def test_missing_account_url_rejected_before_request(self):
        self.net.account = messages.RegistrationResource(
            body=messages.Registration(), uri=None)
        with pytest.raises(ValueError):
            self.cli.key_change(self.new_key)
        self.net.post.assert_not_called()

    def test_missing_key_rejected_before_request(self):
        self.net.key = None
        with pytest.raises(ValueError):
            self.cli.key_change(self.new_key)
        self.net.post.assert_not_called()


class RawCompactJWSTest(unittest.TestCase):
    """Tests for the raw-payload signing path used by keyChange."""

    def setUp(self):
        self.account = messages.RegistrationResource(
            body=messages.Registration(), uri=ACCOUNT_URL)
        self.net = client.ClientNetwork(KEY, account=self.account)
        self.response = mock.MagicMock(
            ok=True, status_code=http_client.OK, headers={}, links={})
        self.net._send_request = mock.Mock(return_value=self.response)  # pylint: disable=protected-access
        self.net._check_response = mock.Mock(return_value=self.response)  # pylint: disable=protected-access
        self.net._add_nonce = mock.Mock()  # pylint: disable=protected-access
        self.net._get_nonce = mock.Mock(return_value=b'nonce')  # pylint: disable=protected-access

    def test_post_raw_jws_wraps_bytes_in_outer_jws(self):
        payload = b'aaa.bbb.ccc'
        self.net.post_raw_jws(KEY_CHANGE_URL, payload,
                              new_nonce_url=NEW_NONCE_URL)
        sent = self.net._send_request.call_args.kwargs['data']  # pylint: disable=protected-access
        outer = acme_jws.JWS.json_loads(sent)
        assert outer.payload == payload
        assert outer.signature.combined.kid == ACCOUNT_URL
        assert outer.verify(KEY.public_key())

    def test_post_raw_jws_bad_nonce_retried_once(self):
        self.net._check_response.side_effect = [  # pylint: disable=protected-access
            messages.Error.with_code('badNonce'), self.response]
        payload = b'aaa.bbb.ccc'
        result = self.net.post_raw_jws(KEY_CHANGE_URL, payload,
                                       new_nonce_url=NEW_NONCE_URL)
        assert result == self.response
        assert self.net._send_request.call_count == 2  # pylint: disable=protected-access

    def test_post_once_routes_raw_wrapper(self):
        raw = client._RawCompactJWS(b'aaa.bbb.ccc')
        with mock.patch.object(self.net, '_post_raw_jws_once',
                               return_value=self.response) as raw_once:
            assert self.net._post_once(KEY_CHANGE_URL, raw) == self.response  # pylint: disable=protected-access
            raw_once.assert_called_once()
            assert raw_once.call_args[0][1] == b'aaa.bbb.ccc'

    def test_raw_wrapper_rejects_non_bytes(self):
        with pytest.raises(TypeError):
            client._RawCompactJWS('not-bytes')  # type: ignore[arg-type]


class KeyChangeErrorTest(unittest.TestCase):
    """Tests for the key change exception types."""

    def setUp(self):
        self.old_key = KEY
        self.new_key = _fresh_key()

    def test_uncertain_error_message(self):
        cause = requests.exceptions.Timeout('slow')
        error = errors.KeyChangeUncertainError(
            ACCOUNT_URL, self.old_key, self.new_key)
        try:
            raise error from cause
        except errors.KeyChangeUncertainError as caught:
            assert caught.__cause__ is cause
            assert ACCOUNT_URL in str(caught)
            assert caught.old_key == self.old_key
            assert caught.new_key == self.new_key
        else:  # pragma: no cover
            self.fail('KeyChangeUncertainError was not raised')

    def test_local_switch_error_message_variants(self):
        switched = errors.KeyChangeLocalSwitchError(
            ACCOUNT_URL, self.old_key, self.new_key, True)
        assert switched.local_key_switched is True
        assert 'new key' in str(switched)
        not_switched = errors.KeyChangeLocalSwitchError(
            ACCOUNT_URL, self.old_key, self.new_key, False)
        assert not_switched.local_key_switched is False
        assert 'no longer accepted' in str(not_switched)

    def test_errors_share_base_class(self):
        assert issubclass(errors.KeyChangeUncertainError, errors.KeyChangeError)
        assert issubclass(errors.KeyChangeLocalSwitchError, errors.KeyChangeError)
        assert issubclass(errors.KeyChangeError, errors.ClientError)


if __name__ == '__main__':
    import sys
    import pytest as _pytest
    sys.exit(_pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover


class KeyChangeEndToEndTest(unittest.TestCase):
    """End-to-end tests through the in-process fake ACME server.

    The fake server verifies both JWS layers exactly as RFC 8555 requires.
    It lives under acme/examples and is imported by file path because the
    examples directory is not an installed package.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import os
        here = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
        server_path = os.path.join(
            here, 'examples', 'key_change_demo', 'fake_server.py')
        spec = importlib.util.spec_from_file_location(
            'key_change_fake_server', server_path)
        assert spec is not None and spec.loader is not None
        cls.fake_server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fake_server)

    def _make_stack(self, old_key, scenario):
        fs = self.fake_server
        server = fs.FakeACMEServerAdapter(old_key, scenario=scenario)
        directory = messages.Directory({
            'newNonce': fs.NEW_NONCE_URL,
            'newAccount': fs.BASE_URL + '/new-account',
            'newOrder': fs.BASE_URL + '/new-order',
            'keyChange': fs.KEY_CHANGE_URL,
            'meta': messages.Directory.Meta(),
        })
        net = client.ClientNetwork(old_key, verify_ssl=False)
        net.session = requests.Session()
        net.session.mount('http://fake-acme.invalid/', server)
        net.account = messages.RegistrationResource(
            body=messages.Registration(status=messages.STATUS_VALID),
            uri=fs.ACCOUNT_URL)
        return server, client.ClientV2(directory, net), net

    def test_success_end_to_end(self):
        fs = self.fake_server
        old_key, new_key = _fresh_key(), _fresh_key()
        server, cli, net = self._make_stack(old_key, 'success')

        cli.key_change(new_key)

        assert net.key == new_key
        assert net.account['uri'] == fs.ACCOUNT_URL
        assert server.accepts_key(fs.ACCOUNT_URL, new_key)
        assert not server.accepts_key(fs.ACCOUNT_URL, old_key)
        # One outer and one inner JWS were captured and both verify.
        assert len(server.received_outer_jws) == 1
        assert len(server.received_inner_jws) == 1
        outer = server.received_outer_jws[0]
        inner = server.received_inner_jws[0]
        assert outer.verify(old_key.public_key())
        assert inner.verify(new_key.public_key())
        assert inner.signature.combined.kid is None

    def test_bad_old_key_end_to_end(self):
        fs = self.fake_server
        old_key, new_key = _fresh_key(), _fresh_key()
        server, cli, net = self._make_stack(old_key, 'bad_old_key')
        server.override_old_key = _fresh_key().public_key()

        with pytest.raises(messages.Error):
            cli.key_change(new_key)
        # Local identity preserved; server never switched.
        assert net.key == old_key
        assert net.account['uri'] == fs.ACCOUNT_URL
        assert server.accepts_key(fs.ACCOUNT_URL, old_key)

    def test_bad_account_url_end_to_end(self):
        fs = self.fake_server
        old_key, new_key = _fresh_key(), _fresh_key()
        server, cli, net = self._make_stack(old_key, 'bad_account_url')
        server.override_account_url = fs.ACCOUNT_URL + '-other'

        with pytest.raises(messages.Error):
            cli.key_change(new_key)
        assert net.key == old_key
        assert server.accepts_key(fs.ACCOUNT_URL, old_key)
        # The inner JWS still named the real account; the expectation differed.
        inner = server.received_inner_jws[0]
        key_change = messages.KeyChange.json_loads(inner.payload)
        assert key_change.account == fs.ACCOUNT_URL

    def test_lost_response_end_to_end_is_uncertain_and_single_attempt(self):
        fs = self.fake_server
        old_key, new_key = _fresh_key(), _fresh_key()
        server, cli, net = self._make_stack(old_key, 'lost_response')

        with pytest.raises(errors.KeyChangeUncertainError):
            cli.key_change(new_key)

        # The client kept the old identity and sent the request exactly once.
        assert net.key == old_key
        assert len(server.received_outer_jws) == 1
        # But the server did apply the new key.
        assert server.accepts_key(fs.ACCOUNT_URL, new_key)
        assert not server.accepts_key(fs.ACCOUNT_URL, old_key)

    def test_follow_up_order_uses_new_identity(self):
        fs = self.fake_server
        old_key, new_key = _fresh_key(), _fresh_key()
        _, cli, net = self._make_stack(old_key, 'success')
        cli.key_change(new_key)

        nonce = net._get_nonce(  # pylint: disable=protected-access
            fs.BASE_URL + '/new-order', fs.NEW_NONCE_URL)
        order_jws = json_loads_protected(net, fs.BASE_URL + '/new-order', nonce)
        assert order_jws['kid'] == fs.ACCOUNT_URL
        # The signing key is the new key; the old key must not verify it.
        sent = net._wrap_in_jws(  # pylint: disable=protected-access
            messages.NewOrder(identifiers=()), nonce,
            fs.BASE_URL + '/new-order')
        parsed = acme_jws.JWS.json_loads(sent)
        assert parsed.verify(new_key.public_key())
        assert not parsed.verify(old_key.public_key())


def json_loads_protected(net, url, nonce):
    import json as _json
    import josepy as _jose
    sent = net._wrap_in_jws(  # pylint: disable=protected-access
        messages.NewOrder(identifiers=()), nonce, url)
    protected = _json.loads(_jose.b64.b64decode(
        _json.loads(sent)['protected']))
    return protected
