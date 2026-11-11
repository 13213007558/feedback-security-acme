Account Key Rollover (keyChange)
================================

RFC 8555 section 7.3.5 lets a client replace an account's private key
without changing the account itself. Certificate orders, authorizations,
and the account URL ("kid") all keep working; only the key that signs
future requests changes.

The rollover request carries **two nested JWS objects**:

1. an *inner* JWS signed by the **new** key. Its protected header contains
   the new public key as ``jwk`` (and no ``kid``) and its payload is a
   :class:`acme.messages.KeyChange` object naming the account URL and the
   **old** public key. This proves the client holds the new key;
2. an *outer* JWS signed by the **current (old)** key, authenticated with
   the account ``kid``. Its payload is the compact serialization of the
   inner JWS. This proves the client still controls the existing account.

Usage
-----

``new_key`` is supplied by the caller. On success the client's
:class:`~acme.client.ClientNetwork` is switched in place, so later calls
such as :meth:`~acme.client.ClientV2.new_order` automatically sign with the
new key while keeping the same account identity::

    from acme import client, messages
    import josepy as jose

    # acme_client is an existing ClientV2 whose net already holds the
    # account key and account URL.
    new_key = jose.JWKRSA.load(open('new-account-key.pem', 'rb').read())
    acme_client.key_change(new_key)

    # No further wiring is needed: net.key is now new_key and net.account
    # still carries the same account URL.
    orderr = acme_client.new_order(csr_pem)

Handling the four outcomes
--------------------------

``key_change`` deliberately distinguishes a definite rejection from an
uncertain result, because a key change can be applied by the server even
when the response never reaches the client.

- **Success.** The server returns the updated account object. The client
  sets ``net.key`` to the new key and refreshes ``net.account`` before
  returning. Follow-up orders are signed by the new key.
- **Definitive rejection** (any ACME problem document, including
  ``badNonce`` after the built-in retry is exhausted). The local
  ``ClientNetwork`` keeps the old key and account; the exception is the
  :class:`acme.messages.Error` returned by the server.
- **Uncertain result.** If the request cannot be delivered or no response
  comes back (a ``requests.exceptions.RequestException``), the server may
  already have accepted the new key. The client raises
  :class:`acme.errors.KeyChangeUncertainError`, does **not** replay the
  request, and leaves the local key and account untouched. Replaying the
  same inner JWS is unsafe and is never done automatically.
- **Local switch failure.** If the server confirmed the change but the
  client could not update its local identity,
  :class:`acme.errors.KeyChangeLocalSwitchError` is raised. The server's
  new key is authoritative; do not assume the old local key still works.

Both error types expose ``account_url``, ``old_key`` and ``new_key``; the
original exception is available as ``__cause__``.

Confirming which key is actually in effect
------------------------------------------

After an uncertain result, never guess from local state. Ask the server
which key it accepts. The reliable, read-only check is to look up the
account using a key, exactly as account recovery works:

- build a temporary ``ClientNetwork`` with the **candidate** key;
- POST a ``newAccount`` request with ``onlyReturnExisting=True`` to the
  directory's ``newAccount`` URL;
- a ``200`` (with the account ``Location``) means the server recognizes
  that candidate key; an ``urn:ietf:params:acme:error:accountDoesNotExist``
  (or equivalent ``unauthorized``) means it does not.

Probe the new key first and then the old key. Exactly one of them should
be accepted:

- new key accepted, old rejected -> the rollover happened. Adopt the new
  key locally (``net.key = new_key``) and continue;
- old key accepted, new rejected -> the rollover did not happen. Keep the
  old local identity;
- neither accepted -> the account needs out-of-band recovery; do not keep
  retrying keyChange automatically.

Only after this check should a new order be created, so it is signed with
the key the server actually expects. A runnable, self-contained
demonstration of all four outcomes (using an in-process fake server that
verifies both JWS layers) lives under
``acme/examples/key_change_demo``. It generates its keys into a private
temporary directory and logs only public-key thumbprints, so no private
key ever needs to be copied into a log.
