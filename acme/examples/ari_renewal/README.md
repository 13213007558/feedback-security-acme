# ARI renewal drill

A fully offline drill for the ARI-aware renewal planner in
`acme.renewal_planner`. It uses self-signed test certificates, a JSON
fixture instead of a real ACME server, and writes per-certificate state to
a local directory. No real CA is contacted and no certificate is actually
requested.

```sh
python make_test_certs.py        # writes certs/ and ari_fixture.json
python -m acme.renewal_planner --config certs.ini \
    --fixture ari_fixture.json --state-dir state
```

The planner prints, for every certificate in `certs.ini`, the next action
(`wait` or `renew_now`), when to attempt renewal, when the ACME server may
be queried again, and any alerts. Run it twice: the second run reuses the
persisted schedule and does not "query" the fixture again until
`ari_retry_after` has passed.

## The two clocks

The planner keeps two independent times and never mixes them:

- `renew_at` / `scheduled_renewal_time` — when to *attempt renewal*.
  Compared only against the current time to decide `renew_now` vs `wait`.
- `next_ari_check` / `ari_retry_after` — when the service is *allowed to
  ask the server for renewal info again* (the server's `Retry-After`).
  Compared only against the current time to decide whether to fetch ARI.

The re-query clock never triggers or delays a renewal, and the renewal
clock never triggers a server query.

## Decision table

| Situation | renew_at | next_ari_check |
| --- | --- | --- |
| Certificate expired | now (ARI is not queried, per draft-ietf-acme-ari 4.3) | now + default |
| Past local hard deadline (`notAfter - renew_before_expiry`) | now | now + default |
| `ari_retry_after` in the future | persisted schedule, re-clamped to the deadline | unchanged |
| ARI window received | random point in `[window.start, min(window.end, deadline)]` | server `Retry-After` or default |
| Window entirely in the past | now (random point lands in the past) | as above |
| Window beyond the local deadline | the deadline itself + `ari-window-beyond-local-deadline` alert | as above |
| Fetch fails / response unusable | previous schedule or local fallback (2/3 of lifetime, 1/2 if < 10 days), clamped to the deadline | exponential backoff `default * 2^(n-1)`, capped |
| Directory has no `renewalInfo` | local fallback | now + default |

The random spread is sampled only from the window clamped to the local
hard deadline, so a server suggestion can never push a renewal past the
point where local policy requires it to be done.

## Persisted fields

One JSON file per certificate in the state directory, named by the ARI
certID (`base64url(issuer key id).base64url(DER serial)`), so certificates
with the same serial but different issuers get separate files:

- `scheduled_renewal_time` — the renewal clock (ISO 8601, UTC).
- `ari_retry_after` — the re-query clock (ISO 8601, UTC).
- `consecutive_ari_failures` — drives backoff and the `ari-unavailable` alert.
- `last_error` — last fetch/parse error, for diagnostics.

## Restart recovery

- Missing state file: treated as "never ran" — ARI is queried on the next
  run and the local fallback schedule applies until then.
- Corrupt state file: discarded with a warning, same as missing.
- Persisted `scheduled_renewal_time` in the past: renew immediately.
- Persisted schedule beyond the (possibly changed) local hard deadline:
  re-clamped on load.
- Legacy naive timestamps (e.g. certbot's `ari_retry_after`): read as UTC.

## Alert criteria

- `certificate-expired` (critical): the certificate is already expired.
- `past-local-deadline` (critical): the local hard deadline has passed
  without a renewal.
- `approaching-local-deadline` (warning): the deadline is within
  `alert_lead_days`.
- `ari-unavailable` (warning): ARI fetches failed `max_ari_failures`
  times in a row.
- `ari-down-near-deadline` (critical): ARI is failing while the deadline
  is within the lead time.
- `ari-window-beyond-local-deadline` (warning): the server suggested a
  window that local policy cannot honor.

The example CLI exits with status 1 if any critical alert was raised.
