"""ACME errors."""
import datetime
import typing
from typing import Any
from typing import Mapping

from josepy import errors as jose_errors
import josepy as jose
import requests

# We import acme.messages only during type check to avoid circular dependencies. Type references
# to acme.message.* must be quoted to be lazily initialized and avoid compilation errors.
if typing.TYPE_CHECKING:
    from acme import messages  # pragma: no cover


class Error(Exception):
    """Generic ACME error."""


class DependencyError(Error):
    """Dependency error"""


class SchemaValidationError(jose_errors.DeserializationError):
    """JSON schema ACME object validation error."""


class ClientError(Error):
    """Network error."""


class UnexpectedUpdate(ClientError):
    """Unexpected update error."""


class NonceError(ClientError):
    """Server response nonce error."""


class BadNonce(NonceError):
    """Bad nonce error."""
    def __init__(self, nonce: str, error: Exception, *args: Any) -> None:
        super().__init__(*args)
        self.nonce = nonce
        self.error = error

    def __str__(self) -> str:
        return 'Invalid nonce ({0!r}): {1}'.format(self.nonce, self.error)


class MissingNonce(NonceError):
    """Missing nonce error.

    According to the specification an "ACME server MUST include an
    Replay-Nonce header field in each successful response to a POST it
    provides to a client (...)".

    :ivar requests.Response ~.response: HTTP Response

    """
    def __init__(self, response: requests.Response, *args: Any) -> None:
        super().__init__(*args)
        self.response = response

    def __str__(self) -> str:
        return ('Server {0} response did not include a replay '
                'nonce, headers: {1} (This may be a service outage)'.format(
                    self.response.request.method, self.response.headers))


class PollError(ClientError):
    """Generic error when polling for authorization fails.

    This might be caused by either timeout (`exhausted` will be non-empty)
    or by some authorization being invalid.

    :ivar exhausted: Set of `.AuthorizationResource` that didn't finish
        within max allowed attempts.
    :ivar updated: Mapping from original `.AuthorizationResource`
        to the most recently updated one

    """
    def __init__(self, exhausted: set['messages.AuthorizationResource'],
                 updated: Mapping['messages.AuthorizationResource',
                                  'messages.AuthorizationResource']
                 ) -> None:
        self.exhausted = exhausted
        self.updated = updated
        super().__init__()

    @property
    def timeout(self) -> bool:
        """Was the error caused by timeout?"""
        return bool(self.exhausted)

    def __repr__(self) -> str:
        return '{0}(exhausted={1!r}, updated={2!r})'.format(
            self.__class__.__name__, self.exhausted, self.updated)


class ValidationError(Error):
    """Error for authorization failures. Contains a list of authorization
    resources, each of which is invalid and should have an error field.
    """
    def __init__(self, failed_authzrs: list['messages.AuthorizationResource']) -> None:
        self.failed_authzrs = failed_authzrs
        super().__init__()

    def __str__(self) -> str:
        msg = []
        for authzr in self.failed_authzrs:
            msg.append(f'Authorization for {authzr.body.identifier.value} ' \
                'failed due to one or more failed challenges:')
            for challenge in authzr.body.challenges:
                msg.append(f'  Challenge {challenge.chall.typ} failed ' \
                    f'with error {str(challenge.error)}')
        return '\n'.join(msg)


class TimeoutError(Error):  # pylint: disable=redefined-builtin
    """Error for when polling an authorization or an order times out."""


class IssuanceError(Error):
    """Error sent by the server after requesting issuance of a certificate."""

    def __init__(self, error: 'messages.Error') -> None:
        """Initialize.

        :param messages.Error error: The error provided by the server.
        """
        self.error = error
        super().__init__()


class ConflictError(ClientError):
    """Error for when the server returns a 409 (Conflict) HTTP status.

    In the version of ACME implemented by Boulder, this is used to find an
    account if you only have the private key, but don't know the account URL.

    Also used in V2 of the ACME client for the same purpose.
    """
    def __init__(self, location: str) -> None:
        self.location = location
        super().__init__()


class WildcardUnsupportedError(Error):
    """Error for when a wildcard is requested but is unsupported by ACME CA."""


class ARIError(ClientError):
    """An error occurred during an ARI request and we want to suggest a Retry-After time."""
    def __init__(self, message: str, retry_after: datetime.datetime) -> None:
        super().__init__(message, retry_after)
        self.retry_after = retry_after


class KeyChangeError(ClientError):
    """Base class for errors raised while rolling over an account key.

    See RFC 8555 section 7.3.5.
    """

    def __init__(self, account_url: str, old_key: 'jose.JWK',
                 new_key: 'jose.JWK', *args: Any) -> None:
        super().__init__(*args)
        self.account_url = account_url
        self.old_key = old_key
        self.new_key = new_key


class KeyChangeUncertainError(KeyChangeError):
    """The outcome of a keyChange request could not be determined.

    Raised when the keyChange request could not be delivered, or no
    response was received, because of a transport-level failure. The
    server may or may not have applied the new key, so the request must
    not be retried blindly. The local :class:`~acme.client.ClientNetwork`
    keeps the old key and account identity until the server's state has
    been checked out of band.

    The original transport error is available through ``__cause__``.
    """

    def __str__(self) -> str:
        return (
            'keyChange request to {url} could not be completed: {cause}. '
            'The server may already have accepted the new key, so the request '
            'was not retried and the local account key was left unchanged. '
            'Check which key the server accepts before trying again.'.format(
                url=self.account_url,
                cause=self.__cause__ if self.__cause__ is not None else 'no response received'))


class KeyChangeLocalSwitchError(KeyChangeError):
    """The server accepted the key change but the local identity could not be switched.

    The server confirmed the keyChange, so the new key is authoritative on
    the server. If the local :class:`~acme.client.ClientNetwork` could be
    updated it already holds the new key; otherwise it still holds the old
    key, which the server no longer accepts. Do not assume the old local
    state is valid.

    The original local failure is available through ``__cause__``.
    """

    def __init__(self, account_url: str, old_key: 'jose.JWK', new_key: 'jose.JWK',
                 local_key_switched: bool, *args: Any) -> None:
        super().__init__(account_url, old_key, new_key, *args)
        self.local_key_switched = local_key_switched

    def __str__(self) -> str:
        if self.local_key_switched:
            detail = ('the local key was switched to the new key, but updating the '
                      'local account object failed')
        else:
            detail = ('neither the local key nor the local account object could be '
                      'switched; the old local key is no longer accepted by the server')
        return (
            'keyChange to {url} was accepted by the server, but {detail}. '
            'Do not assume the old local state is valid.'.format(
                url=self.account_url, detail=detail))
