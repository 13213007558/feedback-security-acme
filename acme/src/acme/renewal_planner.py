"""ARI-aware renewal scheduling for a certificate renewal service.

This module turns the ACME Renewal Information (ARI) support in
:mod:`acme.client` into a runnable scheduling strategy. It deliberately keeps
two clocks apart:

* ``renew_at`` -- when the service should *attempt renewal* of a certificate.
* ``next_ari_check`` -- when the service is *allowed to ask the ACME server
  for renewal information again* (the server supplied ``Retry-After``).

The two values are computed, persisted, and compared independently. The
re-query clock never decides whether to renew, and the renewal clock never
decides when to talk to the server.

Local safety policy always wins over server suggestions: the effective
renewal window is clamped to a locally computed hard deadline
(``notAfter - renew_before_expiry``), and the randomized spread inside the
suggested window is sampled only from the clamped interval, so a server
response can never push a renewal past the point where local policy requires
the renewal to be done.

No network access happens here: the ARI fetch is injected as a callable, so
production code can wire in :class:`acme.client.ClientV2` while tests and
local drills use fixtures.
"""

import argparse
import configparser
import datetime
import hashlib
import json
import logging
import os
import random
import sys
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Callable, Optional

from cryptography import x509

logger = logging.getLogger(__name__)

RENEW_NOW = "renew_now"
WAIT = "wait"

WARNING = "warning"
CRITICAL = "critical"

#: Lifetime under which the local fallback renewal time is half-way through
#: the certificate lifetime instead of two-thirds (mirrors certbot).
SHORT_LIVED_THRESHOLD = datetime.timedelta(days=10)


class AriFetchError(Exception):
    """The ARI endpoint could not be reached or returned unusable data."""


@dataclass(frozen=True)
class RenewalPolicy:
    """Local safety limits that server suggestions may never override."""
    #: Renewal must be completed this long before notAfter, no matter what
    #: the server suggests.
    renew_before_expiry: datetime.timedelta = datetime.timedelta(days=30)
    #: Default gap between ARI queries when the server sends no Retry-After.
    default_retry_after: datetime.timedelta = datetime.timedelta(hours=6)
    #: Upper bound for the re-query backoff after fetch failures.
    max_retry_after: datetime.timedelta = datetime.timedelta(hours=24)
    #: Start alerting when the hard deadline is this close.
    alert_lead_time: datetime.timedelta = datetime.timedelta(days=7)
    #: Consecutive ARI failures before a warning alert is raised.
    max_ari_failures: int = 3


@dataclass(frozen=True)
class ARIResponse:
    """Raw ARI answer: suggested window plus optional re-query time."""
    window_start: datetime.datetime
    window_end: datetime.datetime
    retry_after: Optional[datetime.datetime] = None


#: Injected ARI fetcher. Returns None when the directory has no
#: "renewalInfo" endpoint, an ARIResponse on success, and raises
#: AriFetchError on transport errors or unusable responses.
AriFetcher = Callable[[bytes], Optional[ARIResponse]]


@dataclass(frozen=True)
class Alert:
    """An operational alert produced while planning."""
    level: str
    code: str
    message: str


@dataclass(frozen=True)
class CertState:
    """State persisted per certificate between service runs.

    All datetimes are timezone-aware UTC. ``scheduled_renewal_time`` and
    ``ari_retry_after`` are the two independent clocks described in the
    module docstring.
    """
    scheduled_renewal_time: Optional[datetime.datetime] = None
    ari_retry_after: Optional[datetime.datetime] = None
    consecutive_ari_failures: int = 0
    last_error: Optional[str] = None

    def to_dict(self) -> dict:
        def fmt(value: Optional[datetime.datetime]) -> Optional[str]:
            return value.isoformat() if value is not None else None
        return {
            "scheduled_renewal_time": fmt(self.scheduled_renewal_time),
            "ari_retry_after": fmt(self.ari_retry_after),
            "consecutive_ari_failures": self.consecutive_ari_failures,
            "last_error": self.last_error,
        }

    @staticmethod
    def _parse(value: object) -> Optional[datetime.datetime]:
        if not isinstance(value, str) or not value:
            return None
        parsed = datetime.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            # Legacy state written by clients that stored naive datetimes
            # (e.g. certbot's ari_retry_after) is interpreted as UTC.
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed

    @classmethod
    def from_dict(cls, data: dict) -> "CertState":
        if not isinstance(data, dict):
            raise ValueError("state must be a JSON object")
        failures = data.get("consecutive_ari_failures", 0)
        if not isinstance(failures, int) or failures < 0:
            raise ValueError("invalid consecutive_ari_failures")
        last_error = data.get("last_error")
        if last_error is not None and not isinstance(last_error, str):
            raise ValueError("invalid last_error")
        return cls(
            scheduled_renewal_time=cls._parse(data.get("scheduled_renewal_time")),
            ari_retry_after=cls._parse(data.get("ari_retry_after")),
            consecutive_ari_failures=failures,
            last_error=last_error,
        )


@dataclass(frozen=True)
class Plan:
    """The next actions for one certificate."""
    action: str
    renew_at: datetime.datetime
    next_ari_check: datetime.datetime
    alerts: tuple = dataclass_field(default_factory=tuple)
    state: CertState = CertState()
    reason: str = ""


def _default_local_renewal_time(cert: x509.Certificate) -> datetime.datetime:
    """Local fallback renewal time based on certificate lifetime."""
    not_before = cert.not_valid_before_utc
    lifetime = cert.not_valid_after_utc - not_before
    if lifetime < SHORT_LIVED_THRESHOLD:
        return not_before + lifetime / 2
    return not_before + lifetime * 2 / 3


def _aware_utc(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def plan_renewal(now: datetime.datetime,
                 cert_pem: bytes,
                 state: CertState,
                 policy: RenewalPolicy,
                 fetch_ari: AriFetcher,
                 rand: Callable[[], float] = random.random) -> Plan:
    """Decide the next renewal attempt and the next ARI query for a cert.

    :param now: current time (timezone-aware).
    :param cert_pem: PEM-encoded certificate currently in use.
    :param state: persisted state from the previous run (``CertState()`` if none).
    :param policy: local safety policy; always wins over server suggestions.
    :param fetch_ari: injected ARI fetcher (see :data:`AriFetcher`).
    :param rand: random source returning floats in [0.0, 1.0); injectable so
        drills and tests can control the spread inside the window.

    :returns: a :class:`Plan` whose ``state`` should be persisted.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    alerts: list[Alert] = []
    cert = x509.load_pem_x509_certificate(cert_pem)
    not_after = cert.not_valid_after_utc
    hard_deadline = not_after - policy.renew_before_expiry
    local_default = min(_default_local_renewal_time(cert), hard_deadline)

    # Per draft-ietf-acme-ari section 4.3, clients MUST NOT query renewal
    # info for an expired certificate. Renew immediately instead.
    if not_after <= now:
        alerts.append(Alert(CRITICAL, "certificate-expired",
                            f"certificate expired at {not_after.isoformat()}"))
        return Plan(RENEW_NOW, renew_at=now,
                    next_ari_check=now + policy.default_retry_after,
                    alerts=tuple(alerts), state=state,
                    reason="certificate expired; ARI is not queried after expiry")

    # Past the local hard deadline the certificate must be renewed now;
    # asking the server for a suggestion would only add delay.
    if hard_deadline <= now:
        alerts.append(Alert(CRITICAL, "past-local-deadline",
                            f"local renewal deadline {hard_deadline.isoformat()} has passed"))
        return Plan(RENEW_NOW, renew_at=now,
                    next_ari_check=now + policy.default_retry_after,
                    alerts=tuple(alerts), state=state,
                    reason="local hard deadline reached; renewing without ARI")

    # The re-query clock says we may not talk to the server yet: reuse the
    # persisted renewal schedule, re-clamped to the local deadline in case
    # policy changed or the certificate was replaced while we were down.
    if (state.ari_retry_after is not None and now < state.ari_retry_after
            and state.scheduled_renewal_time is not None):
        renew_at = min(state.scheduled_renewal_time, hard_deadline)
        new_state = CertState(renew_at, state.ari_retry_after,
                              state.consecutive_ari_failures, state.last_error)
        plan = Plan(RENEW_NOW if renew_at <= now else WAIT, renew_at,
                    state.ari_retry_after, tuple(alerts), new_state,
                    "reusing persisted schedule; ARI re-query not due until "
                    f"{state.ari_retry_after.isoformat()}")
        return _with_deadline_alerts(plan, now, hard_deadline, policy)

    try:
        response = fetch_ari(cert_pem)
        if response is not None:
            window_start = _aware_utc(response.window_start)
            window_end = _aware_utc(response.window_end)
            if window_end <= window_start:
                raise AriFetchError(
                    "suggestedWindow end must be after start "
                    f"(got {window_start.isoformat()} .. {window_end.isoformat()})")
    except Exception as error:  # transport errors and unusable responses
        failures = state.consecutive_ari_failures + 1
        backoff = policy.default_retry_after * 2 ** (failures - 1)
        next_check = now + min(backoff, policy.max_retry_after)
        renew_at = min(state.scheduled_renewal_time or local_default, hard_deadline)
        if failures >= policy.max_ari_failures:
            alerts.append(Alert(
                WARNING, "ari-unavailable",
                f"ARI fetch failed {failures} times in a row: {error}"))
        new_state = CertState(renew_at, next_check, failures, str(error))
        plan = Plan(RENEW_NOW if renew_at <= now else WAIT, renew_at, next_check,
                    tuple(alerts), new_state,
                    f"ARI unavailable ({error}); using local fallback schedule")
        return _with_deadline_alerts(plan, now, hard_deadline, policy)

    if response is None:
        renew_at = local_default
        next_check = now + policy.default_retry_after
        new_state = CertState(renew_at, next_check, 0, None)
        plan = Plan(RENEW_NOW if renew_at <= now else WAIT, renew_at, next_check,
                    tuple(alerts), new_state,
                    "directory has no renewalInfo endpoint; using local schedule")
        return _with_deadline_alerts(plan, now, hard_deadline, policy)

    # Clamp the server window to the local hard deadline, then sample the
    # random spread from the clamped interval only.
    effective_end = min(window_end, hard_deadline)
    if window_start >= effective_end:
        renew_at = effective_end
        alerts.append(Alert(
            WARNING, "ari-window-beyond-local-deadline",
            f"server window {window_start.isoformat()}..{window_end.isoformat()} "
            f"is outside the local deadline {hard_deadline.isoformat()}"))
    else:
        spread = (effective_end - window_start).total_seconds()
        renew_at = window_start + datetime.timedelta(seconds=rand() * spread)
    retry_after = response.retry_after
    next_check = (_aware_utc(retry_after) if retry_after is not None
                  else now + policy.default_retry_after)
    new_state = CertState(renew_at, next_check, 0, None)
    plan = Plan(RENEW_NOW if renew_at <= now else WAIT, renew_at, next_check,
                tuple(alerts), new_state,
                f"ARI window {window_start.isoformat()}..{window_end.isoformat()} "
                f"clamped to local deadline {hard_deadline.isoformat()}")
    return _with_deadline_alerts(plan, now, hard_deadline, policy)


def _with_deadline_alerts(plan: Plan, now: datetime.datetime,
                          hard_deadline: datetime.datetime,
                          policy: RenewalPolicy) -> Plan:
    alerts = list(plan.alerts)
    if hard_deadline - now <= policy.alert_lead_time:
        alerts.append(Alert(
            WARNING, "approaching-local-deadline",
            f"local renewal deadline {hard_deadline.isoformat()} is within "
            f"{policy.alert_lead_time}"))
    if any(a.code == "ari-unavailable" for a in alerts) and \
            any(a.code == "approaching-local-deadline" for a in alerts):
        alerts.append(Alert(
            CRITICAL, "ari-down-near-deadline",
            "ARI is failing while the local renewal deadline is close"))
    return Plan(plan.action, plan.renew_at, plan.next_ari_check,
                tuple(alerts), plan.state, plan.reason)


def cert_state_id(cert_pem: bytes) -> str:
    """Stable per-certificate identifier used for the state file name.

    This is the ARI certID (base64url of the issuer key identifier and the
    DER-encoded serial), so certificates with the same serial but different
    issuers get distinct state files. Certificates without an Authority Key
    Identifier fall back to a digest of the PEM.
    """
    from acme.client import _renewal_info_path_component
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        return _renewal_info_path_component(cert)
    except x509.ExtensionNotFound:
        digest = hashlib.sha256(cert_pem).hexdigest()
        return f"noakid-{digest[:32]}"


def load_state(state_dir: str, cert_pem: bytes) -> CertState:
    """Load persisted state, recovering from missing or corrupt files.

    Restart recovery rules: a missing file means "never ran" and a corrupt
    file is discarded; both yield a fresh state, which makes the next run
    query ARI immediately and fall back to the local schedule.
    """
    path = os.path.join(state_dir, cert_state_id(cert_pem) + ".json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return CertState.from_dict(json.load(f))
    except FileNotFoundError:
        return CertState()
    except (ValueError, KeyError) as e:
        logger.warning("Discarding corrupt ARI state file %s: %s", path, e)
        return CertState(last_error=f"discarded corrupt state: {e}")


def save_state(state_dir: str, cert_pem: bytes, state: CertState) -> str:
    """Persist state atomically; returns the state file path."""
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, cert_state_id(cert_pem) + ".json")
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state.to_dict(), f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp_path, path)
    return path


def fetch_ari_window(acme_client: "object", cert_pem: bytes,
                     default_retry_after: datetime.timedelta =
                     RenewalPolicy.default_retry_after) -> Optional[ARIResponse]:
    """Production fetcher: raw ARI window via an acme ClientV2 instance.

    Unlike ``ClientV2.renewal_time`` this returns the unmodified server
    window so the planner can clamp it against local policy before any
    random spread is applied. Returns None when the directory has no
    "renewalInfo" field and raises AriFetchError otherwise.
    """
    from acme import messages
    from acme.client import _renewal_info_path_component

    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        base_url = acme_client.directory["renewalInfo"]
    except KeyError:
        return None
    url = base_url + "/" + _renewal_info_path_component(cert)
    try:
        resp = acme_client.net.get(url, content_type="application/json")
    except Exception as e:
        raise AriFetchError(f"failed to fetch {url}: {e}") from e
    try:
        info = messages.RenewalInfo.from_json(resp.json())
        window = info.suggested_window
        start, end = window.start, window.end
    except Exception as e:
        raise AriFetchError(f"unparseable renewal info from {url}: {e}") from e
    if start is None or end is None:
        raise AriFetchError(f"renewal info from {url} is missing suggestedWindow fields")
    retry_after = acme_client.retry_after(resp, default_retry_after.seconds)
    return ARIResponse(start, end, retry_after)


def _fixture_fetcher(fixture: dict) -> AriFetcher:
    """Build a fetcher from a JSON fixture for local drills (no network)."""
    def fetch(cert_pem: bytes) -> Optional[ARIResponse]:
        if not fixture.get("renewal_info_available", True):
            return None
        responses = fixture.get("responses", {})
        cert_id = cert_state_id(cert_pem)
        entry = responses.get(cert_id, responses.get("*"))
        if entry is None:
            raise AriFetchError(f"no fixture response for certID {cert_id}")
        if "error" in entry:
            raise AriFetchError(str(entry["error"]))
        retry_after = None
        if "retry_after_seconds" in entry:
            retry_after = (datetime.datetime.now(datetime.timezone.utc)
                           + datetime.timedelta(seconds=entry["retry_after_seconds"]))
        try:
            return ARIResponse(
                datetime.datetime.fromisoformat(entry["window_start"]),
                datetime.datetime.fromisoformat(entry["window_end"]),
                retry_after)
        except (KeyError, ValueError) as e:
            raise AriFetchError(f"bad fixture entry for {cert_id}: {e}") from e
    return fetch


def _policy_from_config(parser: configparser.ConfigParser) -> RenewalPolicy:
    def days(name: str, default: datetime.timedelta) -> datetime.timedelta:
        if parser.has_option("policy", name):
            return datetime.timedelta(days=parser.getfloat("policy", name))
        return default
    def hours(name: str, default: datetime.timedelta) -> datetime.timedelta:
        if parser.has_option("policy", name):
            return datetime.timedelta(hours=parser.getfloat("policy", name))
        return default
    failures = (parser.getint("policy", "max_ari_failures")
                if parser.has_option("policy", "max_ari_failures")
                else RenewalPolicy.max_ari_failures)
    return RenewalPolicy(
        renew_before_expiry=days("renew_before_expiry_days",
                                 RenewalPolicy.renew_before_expiry),
        default_retry_after=hours("default_retry_after_hours",
                                  RenewalPolicy.default_retry_after),
        max_retry_after=hours("max_retry_after_hours",
                              RenewalPolicy.max_retry_after),
        alert_lead_time=days("alert_lead_days", RenewalPolicy.alert_lead_time),
        max_ari_failures=failures)


def main(argv: Optional[list] = None) -> int:
    """Plan the next action for every certificate in an INI config.

    Uses a JSON fixture instead of a real ACME server, so this runs fully
    offline and shows, per certificate, when to renew and when to re-query.
    """
    argp = argparse.ArgumentParser(prog="acme.renewal_planner")
    argp.add_argument("--config", required=True,
                      help="INI file with a [policy] section and one "
                           "[cert:<name>] section per certificate")
    argp.add_argument("--fixture", required=True,
                      help="JSON file with fake ARI responses keyed by certID")
    argp.add_argument("--state-dir", required=True,
                      help="directory for per-certificate persisted state")
    argp.add_argument("--now", help="ISO 8601 timestamp to use as 'now' "
                                    "(defaults to the real current time)")
    args = argp.parse_args(argv)

    parser = configparser.ConfigParser()
    with open(args.config, "r", encoding="utf-8") as f:
        parser.read_file(f)
    policy = _policy_from_config(parser)
    with open(args.fixture, "r", encoding="utf-8") as f:
        fetch_ari = _fixture_fetcher(json.load(f))
    now = (datetime.datetime.fromisoformat(args.now) if args.now
           else datetime.datetime.now(datetime.timezone.utc))
    now = _aware_utc(now)

    cert_sections = [s for s in parser.sections() if s.startswith("cert:")]
    if not cert_sections:
        print("no [cert:<name>] sections in config", file=sys.stderr)
        return 2
    exit_code = 0
    for section in cert_sections:
        name = section[len("cert:"):]
        with open(parser.get(section, "path"), "rb") as f:
            cert_pem = f.read()
        state = load_state(args.state_dir, cert_pem)
        plan = plan_renewal(now, cert_pem, state, policy, fetch_ari)
        save_state(args.state_dir, cert_pem, plan.state)
        print(f"[{name}]")
        print(f"  action:         {plan.action}")
        print(f"  renew_at:       {plan.renew_at.isoformat()}")
        print(f"  next_ari_check: {plan.next_ari_check.isoformat()}")
        print(f"  reason:         {plan.reason}")
        for alert in plan.alerts:
            print(f"  ALERT {alert.level}: {alert.code}: {alert.message}")
            if alert.level == CRITICAL:
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
