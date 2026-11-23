# saas-governance-kit

Python tooling for SaaS identity and access governance: a SCIM 2.0 server, SAML and OIDC validators, a Slack access-request app and audit log client, a GitHub organization auditor, and a SOC 2 evidence mapper, all runnable and testable locally.

Nothing here has been run against a real Okta tenant, Slack Enterprise Grid or GitHub Enterprise. See [What is tested vs not tested](#what-is-tested-vs-not-tested).

## Quick start

Python 3.11 or newer.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check .
```

Output from a real run of the last two:

```
88 passed, 1 warning in 1.75s
All checks passed!
```

### Run the SCIM server

```bash
export SCIM_BEARER_TOKEN=demo-token
scim-server --port 8080 --store ./scim-data.json &

curl -s -X POST localhost:8080/scim/v2/Users \
  -H 'Authorization: Bearer demo-token' -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com"}'
```

Real response (trimmed ids are real values from that run):

```json
{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@example.com",
    "id": "82c4e7394f874a6e85201c96e80c7f2d",
    "active": true,
    "meta": {
        "resourceType": "User",
        "created": "2026-11-23T03:56:06Z",
        "lastModified": "2026-11-23T03:56:06Z",
        "location": "http://localhost:8080/scim/v2/Users/82c4e7394f874a6e85201c96e80c7f2d"
    }
}
```

Deprovision with an Okta-style PATCH, and check that a request without the token is refused:

```bash
curl -s -X PATCH localhost:8080/scim/v2/Users/$ID -H 'Authorization: Bearer demo-token' \
  -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}'
curl -s -o /dev/null -w "no token: %{http_code}\n" localhost:8080/scim/v2/Users
```

```
alice@example.com active = False
no token: 401
```

The same server runs in Docker (built and smoke-tested locally):

```bash
docker build -t saas-governance-kit .
docker run --rm -e SCIM_BEARER_TOKEN=demo-token -p 8080:8080 -v "$PWD/data:/data" saas-governance-kit
```

### Audit a GitHub org and produce SOC 2 evidence (offline fixtures)

```bash
github-audit --org acme --offline-fixtures tests/fixtures/github/acme_routes.json --out gh.json
soc2-report --github gh.json --slack-audit slack.json --scim-store scim-data.json --format md
```

Real output from the fixture run (`gh.json` findings):

```
GH-2FA-001 high Members without two-factor authentication ['bob', 'dave']
GH-BP-001 high Default branch has no protection ['web']
GH-OC-001 medium Outside collaborators have access ['contractor-1']
```

The full Markdown report from that run is in [examples/sample-output/soc2-evidence.md](examples/sample-output/soc2-evidence.md). Against a real org, drop `--offline-fixtures` and set `GITHUB_TOKEN` to a read-only token. `slack.json` comes from `slack-audit-logs` (needs `SLACK_AUDIT_TOKEN`).

## Architecture

```
                    +-------------------+        +----------------------+
 Okta / IdP  -----> | SCIM 2.0 server   | <----- | Slack /access-request |
 (provisioning)     | /Users /Groups    |  PATCH | Bolt app + buttons    |
                    | JSON or memory    |  group +----------+-----------+
                    +---------+---------+  add              |
                              |                            | approvals
 Okta / IdP  -----> +---------+---------+                  v
 (SSO)              | SAML SP validator |         +----------------------+
                    | OIDC ID-token     |         | Slack Audit Logs API |
                    | validator         |         | client (cursor, 429) |
                    +---------+---------+         +----------+-----------+
                              | auth events                  |
                              v                              v
 GitHub REST  ----> +-------------------+         +----------------------+
 (org audit)        | github-audit CLI  | ------> | soc2-report          |
                    | findings JSON     |         | CC6.1 CC6.2 CC6.3    |
                    +-------------------+         | CC7.2 CC8.1          |
                                                  | Markdown / JSON      |
 examples/terraform: GitHub + Slack config-as-code +----------------------+
 (fmt and validate only, never applied)
```

## Components

| Part | Path | Notes |
| --- | --- | --- |
| SCIM 2.0 server | `src/saas_governance_kit/scim` | RFC 7643/7644 subset: Users, Groups, PATCH add/replace/remove, filter `eq ne co sw pr` with `and`, pagination, ServiceProviderConfig, Schemas, ResourceTypes, constant-time bearer check, 409 on duplicate userName, deprovision sets `active: false` |
| SAML SP validator | `.../saml/validator.py` | signxml verification against a pinned IdP cert, Audience, Destination, Recipient, InResponseTo, NotBefore/NotOnOrAfter with skew, replay cache, rejects unsigned, multiple assertions, duplicate IDs and DOCTYPE |
| OIDC validator | `.../oidc/validator.py` | JWKS with kid rotation refresh, algorithm allowlist, rejects `none` and HS* confusion, iss, aud, azp, exp, iat, nonce |
| Slack access request | `.../slack/access_request.py`, `bolt_app.py` | `/access-request <group> <reason>`, Approve and Deny buttons, approver allowlist, no self-approval, adds the requester to a SCIM group |
| Slack audit logs | `.../slack/audit_logs.py` | `https://api.slack.com/audit/v1/logs`, cursor pagination, `Retry-After` handling, summary of privileged events |
| Slack request signing | `.../slack/signing.py` | v0 HMAC-SHA256 with timestamp tolerance; Bolt also verifies the same signature |
| GitHub org audit | `.../github/` | SAML credential authorizations, 2FA-disabled members, default-branch protection (or rulesets), outside collaborators, audit log export |
| Reusable workflow | `.github/workflows/github-org-audit.yml` | read-only token, no OIDC, uploads the report and SOC 2 evidence as artifacts |
| SOC 2 mapping | `.../soc2/` | evidence support only, see the disclaimer below |
| Terraform example | `examples/terraform` | GitHub repos, branch protection, teams; Slack channel and user groups |

Call the reusable workflow from another repo:

```yaml
jobs:
  audit:
    uses: gerardrecinto/saas-governance-kit/.github/workflows/github-org-audit.yml@main
    with:
      org: your-org
    secrets:
      audit_token: ${{ secrets.ORG_AUDIT_TOKEN }}
```

## SOC 2 mapping

`soc2-report` maps findings to AICPA Trust Services Criteria CC6.1, CC6.2, CC6.3, CC7.2 and CC8.1. It is evidence support. It is not a SOC 2 report, an attestation, a certification or a compliance claim. Whether a control is designed and operating effectively is for an auditor to decide.

## What is tested vs not tested

| Area | Tested here | Not tested |
| --- | --- | --- |
| SCIM server | 15 pytest cases over FastAPI TestClient, including an Okta-style PATCH and a JSON-file store reload; a manual curl run and a Docker smoke test | Real Okta, Entra ID or any IdP provisioning connector; interop with vendor SCIM quirks beyond the Okta-style payload |
| SAML validator | 23 cases with a self-generated test IdP key and cert: valid, unsigned, tampered, wrong key, expired, skew, audience, destination, InResponseTo, replay, wrapping, DOCTYPE | Any real IdP's metadata or signatures; encrypted assertions (rejected, not supported); SP-initiated AuthnRequest generation; logout |
| OIDC validator | 22 cases with locally generated RSA and EC keys, including `none`, HS256 confusion, kid rotation | A real provider's discovery document and JWKS over the network |
| Slack access request | Handler unit tests with fake clients, SCIM client over a mock transport, Bolt dispatch against a local fake Slack Web API with signature checks | Real Slack workspace, real tokens, interactive button payloads from Slack, Enterprise Grid |
| Slack audit logs | 7 cases against hand-written fixtures that follow the documented response shape; 429 and cursor handling via mock transport | The live Audit Logs API on a real Enterprise Grid org; real action names beyond the few used |
| GitHub audit | 7 cases against fixtures and a mock transport, including Link pagination and rate-limit backoff | A real GitHub Enterprise org or GHES; SSO enforcement (not readable via REST, only credential authorizations are checked) |
| SOC 2 mapping | 4 cases on fixture-derived input | Any auditor review; mapping choices are mine and are not an auditor-approved control matrix |
| Terraform | `terraform fmt -check`, `terraform init -backend=false`, `terraform validate` | `plan` and `apply` (never run); behavior of the community Slack provider |
| Reusable workflow | YAML written and reviewed | Not yet run against a real org |

The fixtures were written by hand to match the documented API shapes. They are not captures from a real tenant.

## Security notes

See [SECURITY.md](SECURITY.md). The SCIM server uses one static bearer token; put it behind TLS. The SAML replay cache is in memory, so use a shared store if you run more than one instance.

Troubleshooting for common federation errors is in [docs/RUNBOOK.md](docs/RUNBOOK.md).

## License

MIT
