ACME Account Key Rollover Demo (RFC 8555 7.3.5)
===============================================

A runnable demonstration of ``ClientV2.key_change`` against a fake ACME
server that fully verifies both JWS layers of a keyChange request.

Run it from the repository root::

    python acme/examples/key_change_demo/demo.py

The fake server (:mod:`fake_server`) is mounted directly onto a
``requests.Session`` as a transport adapter, so no network socket or port
binding is required and every request still travels through the real
``acme.client`` signing code.

Scenarios shown:

* ``success`` - both JWS layers accepted; the local identity is switched
  and a follow-up new-order JWS is signed by the new key with the same
  account ``kid``;
* ``bad_old_key`` - the inner ``oldKey`` does not match the server's
  record; the request is rejected and the local identity is unchanged;
* ``bad_account_url`` - the inner ``account`` does not match the outer
  ``kid``; the request is rejected and the local identity is unchanged;
* ``lost_response`` - the server applies the change but the response is
  lost. The client raises ``KeyChangeUncertainError``, keeps the old local
  identity, sends the request exactly once, and then probes which key the
  server actually accepts.

Key handling
------------

All private keys are generated into a private directory created with
``tempfile.mkdtemp`` (mode ``0600``). The demo prints only SHA-256
thumbprints of the *public* keys, so no private key material is logged and
there is nothing to copy by hand. Delete the temporary directory shown at
the end of the run when you are done.
