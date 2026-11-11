"""In-process fake ACME server demonstrating RFC 8555 keyChange verification.

A real ACME keyChange exchange is two nested JWS objects sent over HTTPS.
This module fakes only the HTTP transport: it is mounted directly onto a
:class:`requests.Session` as a transport adapter, so no network socket is
needed and every request still goes through the real ``requests`` /
``acme.client`` signing code path.

The server keeps an authoritative map of account URL -> accepted public key
and fully verifies both JWS layers of every keyChange request:

* the outer JWS must be signed by the key currently registered for the
  account named in its "kid" header;
* its payload must be the compact serialization of an inner JWS;
* the inner JWS must be signed by the "jwk" it carries;
* its payload must name the same account and the currently registered
  (old) public key.

It is scriptable to produce the four scenarios used by the demo:

``"success"``          accept the rollover and switch the stored key;
``"bad_old_key"``      reject with ``malformed`` because the inner "oldKey"
                       does not match the registered key;
``"bad_account_url"``  reject with ``malformed`` because the inner "account"
                       does not match the outer "kid";
``"lost_response"``    accept and apply the rollover, then drop the response
                       by raising a transport error (simulating a lost reply
                       after server-side acceptance).
"""
from __future__ import annotations

import base64
import json
from typing import Any

import josepy as jose
import requests
from requests.adapters import BaseAdapter
from requests.models import Response

from acme import jws as acme_jws
from acme import messages

BASE_URL = 'http://fake-acme.invalid/acme'
ACCOUNT_URL = BASE_URL + '/acct/1'
KEY_CHANGE_URL = BASE_URL + '/key-change'
NEW_NONCE_URL = BASE_URL + '/new-nonce'


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _problem(status_code: int, code: str, detail: str) -> Response:
    response = Response()
    response.status_code = status_code
    response.headers['Content-Type'] = 'application/problem+json'
    response._content = json.dumps({
        'type': messages.ERROR_PREFIX + code,
        'status': status_code,
        'detail': detail,
    }).encode('utf-8')
    return response


class _LostResponse(requests.exceptions.ConnectionError):
    """Raised after the server already applied the change but cannot reply."""


class FakeACMEServerAdapter(BaseAdapter):
    """Transport adapter that emulates the ACME endpoints used by the demo."""

    def __init__(self, initial_key: jose.JWK, scenario: str = 'success') -> None:
        if scenario not in ('success', 'bad_old_key', 'bad_account_url',
                            'lost_response'):
            raise ValueError(f'Unknown scenario: {scenario!r}')
        self.scenario = scenario
        # Authoritative server-side account state.
        self.accounts: dict[str, jose.JWK] = {ACCOUNT_URL: initial_key.public_key()}
        self._nonce_counter = 0
        # Every JWS the server received is retained for inspection.
        self.received_outer_jws: list[acme_jws.JWS] = []
        self.received_inner_jws: list[acme_jws.JWS] = []
        # Test hooks that rewrite the parsed inner KeyChange so the server can
        # demonstrate its inner-payload validation without the client noticing.
        self.override_old_key: jose.JWK | None = None
        self.override_account_url: str | None = None

    def close(self) -> None:  # pragma: no cover - BaseAdapter interface
        pass

    def _fresh_nonce(self) -> str:
        self._nonce_counter += 1
        return _b64url(f'nonce-{self._nonce_counter}'.encode())

    def _json_response(self, payload: dict[str, Any], status_code: int = 200) -> Response:
        response = Response()
        response.status_code = status_code
        response.headers['Content-Type'] = 'application/json'
        response.headers['Replay-Nonce'] = self._fresh_nonce()
        response._content = json.dumps(payload).encode('utf-8')
        return response

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any
             ) -> Response:
        url = request.url
        if url == NEW_NONCE_URL and request.method == 'HEAD':
            response = Response()
            response.status_code = 200
            response.headers['Replay-Nonce'] = self._fresh_nonce()
            return response
        if url == KEY_CHANGE_URL and request.method == 'POST':
            return self._handle_key_change(request)
        return _problem(404, 'malformed', f'No fake endpoint for {request.method} {url}')

    def _handle_key_change(self, request: requests.PreparedRequest) -> Response:
        try:
            outer = acme_jws.JWS.json_loads(request.body)
        except Exception as error:  # pylint: disable=broad-except
            return _problem(400, 'malformed', f'outer JWS is not parseable: {error}')
        self.received_outer_jws.append(outer)

        outer_headers = outer.signature.combined
        kid = outer_headers.kid
        if kid not in self.accounts:
            return _problem(400, 'accountDoesNotExist',
                            f'unknown account URL in outer kid: {kid!r}')
        registered_old_key = self.accounts[kid]
        if not outer.verify(registered_old_key):
            return _problem(403, 'unauthorized',
                            'outer JWS is not signed by the registered account key')

        # Outer payload is the compact-serialized inner JWS. Parse it with
        # the ACME JWS class so its url/kid/jwk headers are recognized.
        inner_compact = outer.payload
        try:
            inner = acme_jws.JWS.from_compact(inner_compact)
        except Exception as error:  # pylint: disable=broad-except
            return _problem(400, 'malformed',
                            f'outer payload is not a compact inner JWS: {error}')
        self.received_inner_jws.append(inner)

        inner_headers = inner.signature.combined
        new_key = inner_headers.jwk
        if new_key is None:
            return _problem(400, 'malformed', 'inner JWS header is missing "jwk"')
        if inner_headers.kid is not None:
            return _problem(400, 'malformed', 'inner JWS must not carry a "kid"')
        if inner_headers.url != KEY_CHANGE_URL:
            return _problem(400, 'malformed',
                            f'inner url {inner_headers.url!r} != {KEY_CHANGE_URL!r}')
        if not inner.verify(new_key):
            return _problem(403, 'unauthorized',
                            'inner JWS is not signed by the "jwk" it carries')

        try:
            key_change = messages.KeyChange.json_loads(inner.payload)
        except Exception as error:  # pylint: disable=broad-except
            return _problem(400, 'malformed',
                            f'inner payload is not a KeyChange object: {error}')

        expected_account = (self.override_account_url
                            if self.override_account_url is not None else kid)
        if key_change.account != expected_account:
            return _problem(400, 'malformed',
                            f'inner account {key_change.account!r} does not match '
                            f'the account URL the server requires {expected_account!r}')
        expected_old_key = (self.override_old_key
                            if self.override_old_key is not None else registered_old_key)
        if key_change.oldKey != expected_old_key:
            return _problem(400, 'malformed',
                            'inner oldKey does not match the key the server '
                            'has on record for the account')

        # All checks passed: the rollover is authoritative from here on.
        self.accounts[kid] = new_key

        if self.scenario == 'lost_response':
            # The server has switched its stored key, but the client never
            # learns the outcome.
            raise _LostResponse(
                'connection reset after server applied keyChange (simulated)')

        account_body = messages.Registration(status=messages.STATUS_VALID).to_json()
        return self._json_response(account_body, status_code=200)

    def accepts_key(self, account_url: str, key: jose.JWK) -> bool:
        """Return whether the server currently accepts ``key`` for the account."""
        return self.accounts.get(account_url) == key.public_key()
