"""End-to-end demonstration of ACME account key rollover (RFC 8555 7.3.5).

Run with::

    python -m acme.examples.key_change_demo.demo

All keys are freshly generated into a private temporary directory created
with :func:`tempfile.mkdtemp`; nothing secret is written into the repository
or printed to the logs. Only public key thumbprints (SHA-256 digests) are
printed, so a human never has to copy a private key into a log line.

Scenarios exercised against the in-process fake ACME server:

1. ``success``          - a normal rollover; both JWS layers are accepted and
                          the local identity is switched.
2. ``bad_old_key``      - the server rejects a request whose inner "oldKey"
                          does not match the registered key; the local
                          identity is provably untouched.
3. ``bad_account_url``  - the server rejects a request whose inner "account"
                          does not match the outer "kid"; the local identity
                          is provably untouched.
4. ``lost_response``    - the server applies the change but the response is
                          lost; the client raises KeyChangeUncertainError,
                          keeps the old local identity, and never replays the
                          request. The demo then shows how to determine which
                          key actually took effect.

The final section shows that a follow-up new order is signed with the new
key and therefore uses the correct post-rollover identity.
"""
from __future__ import annotations

import json
import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
import requests

from acme import client
from acme import errors
from acme import messages
try:  # allow both "python -m" and direct script execution
    from .fake_server import ACCOUNT_URL
    from .fake_server import BASE_URL
    from .fake_server import FakeACMEServerAdapter
    from .fake_server import KEY_CHANGE_URL
    from .fake_server import NEW_NONCE_URL
except ImportError:  # pragma: no cover - direct script fallback
    from fake_server import ACCOUNT_URL
    from fake_server import BASE_URL
    from fake_server import FakeACMEServerAdapter
    from fake_server import KEY_CHANGE_URL
    from fake_server import NEW_NONCE_URL


def _make_rsa_key() -> jose.JWKRSA:
    return jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537, key_size=2048))


def _thumbprint(key: jose.JWK) -> str:
    """Short, non-secret fingerprint safe to put in logs."""
    return jose.b64.b64encode(key.thumbprint()[:12]).decode('ascii')


def _write_private_key(path: str, key: jose.JWK) -> None:
    pem = key.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as handle:
        handle.write(pem)


def _build_client(old_key: jose.JWK, server: FakeACMEServerAdapter
                  ) -> tuple[client.ClientV2, client.ClientNetwork]:
    session = requests.Session()
    session.mount('http://fake-acme.invalid/', server)

    directory = messages.Directory({
        'newNonce': NEW_NONCE_URL,
        'newAccount': BASE_URL + '/new-account',
        'newOrder': BASE_URL + '/new-order',
        'keyChange': KEY_CHANGE_URL,
        'meta': messages.Directory.Meta(),
    })
    net = client.ClientNetwork(old_key, verify_ssl=False, user_agent='key-change-demo')
    net.session = session
    net.account = messages.RegistrationResource(
        body=messages.Registration(status=messages.STATUS_VALID),
        uri=ACCOUNT_URL)
    return client.ClientV2(directory, net), net


def _print_header(title: str) -> None:
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)


def _assert_two_jws_layers(server: FakeACMEServerAdapter) -> None:
    """Show that the captured request really contains two verifiable JWS."""
    outer = server.received_outer_jws[-1]
    inner = server.received_inner_jws[-1]
    outer_headers = outer.signature.combined
    inner_headers = inner.signature.combined
    print('  outer JWS: kid=%s url=%s nonce present=%s'
          % (outer_headers.kid, outer_headers.url, outer_headers.nonce is not None))
    print('  inner JWS: jwk thumbprint=%s url=%s kid=%s'
          % (_thumbprint(inner_headers.jwk), inner_headers.url, inner_headers.kid))
    key_change = messages.KeyChange.json_loads(inner.payload)
    print('  inner payload: account=%s oldKey thumbprint=%s'
          % (key_change.account, _thumbprint(key_change.oldKey)))


def run_scenario(scenario: str, key_dir: str) -> None:
    _print_header('Scenario: %s' % scenario)
    old_key = _make_rsa_key()
    new_key = _make_rsa_key()
    _write_private_key(os.path.join(key_dir, f'{scenario}-old.pem'), old_key)
    _write_private_key(os.path.join(key_dir, f'{scenario}-new.pem'), new_key)
    print('  old key thumbprint: %s' % _thumbprint(old_key))
    print('  new key thumbprint: %s' % _thumbprint(new_key))

    server = FakeACMEServerAdapter(old_key, scenario=scenario)
    acme_client, net = _build_client(old_key, server)

    if scenario == 'bad_old_key':
        # The server expects a different oldKey than the one the client
        # proves it still holds (e.g. its record was rolled out of band).
        # Both JWS signatures stay valid; only the inner "oldKey" mismatches.
        foreign_key = _make_rsa_key()
        server.override_old_key = foreign_key.public_key()
        print('  server expects inner oldKey thumbprint=%s'
              % _thumbprint(foreign_key))
    elif scenario == 'bad_account_url':
        # The server expects the inner "account" to name a different URL than
        # the outer "kid" the client authenticates with.
        server.override_account_url = ACCOUNT_URL + '-other'
        print('  server expects inner account=%r' % server.override_account_url)

    local_key_before = net.key
    local_account_before = net.account
    try:
        acme_client.key_change(new_key)
    except messages.Error as error:
        print('  REJECTED by server: %s' % error)
        print('  local key still old? %s (thumbprint=%s)'
              % (net.key == local_key_before, _thumbprint(net.key)))
        print('  local account unchanged? %s (uri=%r)'
              % (net.account == local_account_before, net.account['uri']))
        print('  server still accepts old key? %s'
              % server.accepts_key(ACCOUNT_URL, old_key))
        return
    except errors.KeyChangeUncertainError as error:
        print('  UNCERTAIN outcome: %s' % error)
        print('  local key still old? %s (thumbprint=%s)'
              % (net.key == old_key, _thumbprint(net.key)))
        print('  request was sent exactly once? %s'
              % (len(server.received_outer_jws) == 1))
        # Recovery procedure: probe which key the server actually accepts.
        if server.accepts_key(ACCOUNT_URL, new_key):
            print('  -> server now accepts the NEW key; adopt it locally '
                  'before doing anything else.')
            net.key = new_key
        elif server.accepts_key(ACCOUNT_URL, old_key):
            print('  -> server still accepts the OLD key; the rollover did not happen.')
        else:
            print('  -> neither key is accepted; manual account recovery is required.')
        return

    # success path
    _assert_two_jws_layers(server)
    print('  SUCCESS. local key switched? %s (thumbprint=%s)'
          % (net.key == new_key, _thumbprint(net.key)))
    print('  server accepts new key? %s' % server.accepts_key(ACCOUNT_URL, new_key))
    print('  server still accepts old key? %s'
          % server.accepts_key(ACCOUNT_URL, old_key))
    _demonstrate_follow_up_order(acme_client, net, new_key)


def _demonstrate_follow_up_order(acme_client: client.ClientV2,
                                 net: client.ClientNetwork,
                                 new_key: jose.JWK) -> None:
    """A new order must be signed by the post-rollover key and identity."""
    # We don't implement a full order endpoint; instead build the JWS the
    # client would send to newOrder and inspect its protected header.
    new_order_url = BASE_URL + '/new-order'
    nonce = net._get_nonce(  # pylint: disable=protected-access
        new_order_url, acme_client.directory.newNonce)
    order = messages.NewOrder(identifiers=())
    order_jws = json.loads(net._wrap_in_jws(order, nonce, new_order_url))  # pylint: disable=protected-access
    protected = json.loads(jose.b64.b64decode(order_jws['protected']))
    print('  follow-up new-order JWS protected header: %s' % protected)
    print('  -> kid is still %r (account identity unchanged)' % protected.get('kid'))
    print('  -> signing key thumbprint=%s (the NEW key)' % _thumbprint(net.key))
    assert protected.get('kid') == ACCOUNT_URL
    assert net.key == new_key


def main() -> None:
    key_dir = tempfile.mkdtemp(prefix='acme-keychange-demo-')
    print('Test keys are written to a private temporary directory: %s' % key_dir)
    print('Only public key thumbprints are printed below; private keys are not logged.')
    for scenario in ('success', 'bad_old_key', 'bad_account_url', 'lost_response'):
        run_scenario(scenario, key_dir)
    print('\nDemo finished. Inspect/delete the temporary directory when done:')
    print('  ' + key_dir)


if __name__ == '__main__':
    main()
