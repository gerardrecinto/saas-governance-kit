# Runbook: federation and provisioning errors

Each entry lists the symptom, the likely cause and how to confirm it. Error codes in backticks are the `code` values raised by this repo's validators.

## SAML: clock skew (`not_yet_valid`, `expired`, `session_expired`)

Symptom: logins fail with a validity-window error shortly after the IdP issues the assertion, or only on some hosts.

Cause: the SP host clock differs from the IdP clock by more than `clock_skew_seconds` (default in tests is 60, config default is 120).

Check:
1. Compare `date -u` on the SP host with the `IssueInstant` in the decoded response.
2. Check NTP sync (`chronyc tracking` or `timedatectl`).
3. Look at `NotBefore` and `NotOnOrAfter`. Short IdP lifetimes (a few minutes) leave little room for skew.

Fix: correct NTP first. Raise `clock_skew_seconds` only as a short-term measure, and keep it small, since it widens the replay window.

## SAML: audience mismatch (`audience_mismatch`)

Symptom: `audience_mismatch` with the audiences list in the message.

Cause: the IdP app is configured with a different SP entity ID than `SamlConfig.sp_entity_id`. Trailing slashes, `http` vs `https` and copied-over test values are common.

Check: compare `Conditions/AudienceRestriction/Audience` in the decoded assertion with the SP entity ID byte for byte.

Fix: set the Audience (SP entity ID) in the IdP app to exactly the value in config.

## SAML: destination, recipient or InResponseTo mismatch (`destination_mismatch`, `subject_confirmation`, `in_response_to_mismatch`, `unsolicited_response`)

- `destination_mismatch`: the IdP ACS URL differs from `acs_url`. Check scheme, host, port and path, and whether a load balancer rewrites the public URL.
- `in_response_to_mismatch`: the response answers a different AuthnRequest than the one the SP stored, often a user with two login tabs or a lost session store. Restart the login.
- `unsolicited_response`: the IdP started the login (IdP-initiated) and `allow_idp_initiated` is false. Enable it only if you need it, and accept that it removes the InResponseTo protection.

## SAML: signature failures (`bad_signature`, `signature_count`, `signature_location`)

Cause: the IdP rotated its signing certificate, the SP pins an old one, or the response is unsigned or signed in an unexpected place.

Check: compare the certificate in IdP metadata with `idp_cert_pem` (`openssl x509 -noout -fingerprint -sha256`). Confirm the IdP signs the Assertion or the Response, not neither.

Fix: update the pinned certificate. Plan overlap by accepting both certificates during rotation. The validator pins a certificate and ignores the one embedded in the message.

## SAML: replay (`replay`)

Cause: the same assertion ID was posted twice (browser back button, double submit, or an attack). With several SP instances and the in-memory cache, replays can slip through.

Fix: ask the user to restart login. For multiple instances, back `ReplayCache` with a shared store.

## OIDC: token validation (`expired`, `nonce_mismatch`, `unknown_kid`, `alg_not_allowed`)

- `expired`: same clock-skew checks as SAML. Also confirm the app is not reusing an old ID token.
- `nonce_mismatch`: the nonce stored in the session does not match the token. Usually the session was lost between redirect and callback.
- `unknown_kid`: the provider rotated keys. `JwksClient` refreshes once per 30 seconds on an unknown kid. If it persists, check the JWKS URI.
- `alg_not_allowed`: the provider signs with an algorithm outside `allowed_algs`. Add it deliberately, never add `none` or `HS*`.

## SCIM: 409 Conflict on create

Symptom: IdP provisioning reports 409 with `scimType: uniqueness`.

Cause: a user or group with the same `userName` (or group `displayName`) already exists. Matching is case-insensitive.

Check: `GET /scim/v2/Users?filter=userName eq "alice@example.com"`.

Fix: link the existing account instead of creating a new one (most IdPs do an `eq` lookup first and then PATCH). If the existing account is stale, delete it or reconcile the `userName` in the IdP mapping.

## SCIM: 401 Unauthorized

Cause: wrong or missing bearer token, or the token was rotated on the server but not in the IdP. The server compares tokens in constant time and returns the same error for both cases.

Check: `curl -H "Authorization: Bearer $TOKEN" .../scim/v2/ServiceProviderConfig` should return 200.

Fix: update the token in the IdP provisioning settings and in `SCIM_BEARER_TOKEN`.

## SCIM: 400 on PATCH

Cause: payload missing the PatchOp schema, an unsupported `op`, a `remove` without a path, or a filter path that matches nothing (`noTarget`). Group PATCH also fails with `invalidValue` if a member id is not a known user.

Fix: provision the user before adding them to the group. Compare the failing payload against the Okta-style cases in `tests/test_scim.py`.

## Slack: token expiry and auth errors

- `invalid_auth` or `token_expired` from the Audit Logs API: the org-level user token was revoked or rotated. Issue a new token with `auditlogs:read` and update `SLACK_AUDIT_TOKEN`.
- 429 responses: the client waits for `Retry-After` (capped at 120 seconds) and retries up to 5 times, then raises. Narrow the `oldest` and `latest` window or the `action` filter.
- Bolt returns 401 for slash commands: the signing secret is wrong, or the request timestamp is older than 5 minutes (server clock skew again).

## GitHub: audit token problems

- 403 on `/orgs/{org}/members?filter=2fa_disabled`: the token lacks organization admin read access. `GITHUB_TOKEN` from Actions cannot read this; use a fine-grained token or app token.
- `GH-SSO-001` reported but SSO is configured: the credential-authorizations endpoint returned 403 or 404, so the check is inconclusive. Confirm the token scope. SSO enforcement itself is not readable through REST.
- `GH-AL-001`: the audit log endpoint needs GitHub Enterprise Cloud and an admin token.
- Rate limit: the client honors `Retry-After` and `x-ratelimit-reset`, capped at 120 seconds per wait.
