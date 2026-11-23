# SOC 2 evidence support report

> Evidence support only. This output is not a SOC 2 report, attestation, certification or compliance claim. It summarizes machine-collected data from the supplied inputs; control design, operating effectiveness and sampling remain the auditor's determination.

Generated: 2026-11-23T03:56:11Z

| Criterion | Result |
| --- | --- |
| CC6.1 | exceptions_noted |
| CC6.2 | no_exceptions_noted |
| CC6.3 | exceptions_noted |
| CC7.2 | no_exceptions_noted |
| CC8.1 | exceptions_noted |

## CC6.1: Logical access security software, infrastructure and architectures

- [ok] **SAML SSO detected** (github): Credential-authorization endpoint status: enabled. Enforcement is not readable via REST.
- [exception] **Members without 2FA** (github): 2 member(s) without two-factor authentication
  - bob
  - dave

## CC6.2: User registration and authorization; removal of access when no longer needed

- [ok] **Deprovisioned users removed from groups** (scim): 1 user(s), 1 deactivated; 0 deactivated user(s) still in a group

## CC6.3: Role-based access and least privilege

- [exception] **Outside collaborators** (github): 1 outside collaborator(s) with org access
  - contractor-1
- [info] **Privileged role and app changes** (slack): 2 privileged event(s) for review
  - role_change_to_admin by alice@example.com on carol@example.com
  - app_installed by alice@example.com on Deploy Bot

## CC7.2: Monitoring of system components for anomalies and security events

- [ok] **Audit log collected** (slack): 5 entries; 2 failed login(s)
- [ok] **Audit log exported** (github): Audit log status: exported, 2 entries

## CC8.1: Change management authorization and approval

- [exception] **Default branch protected** (github): 2 of 3 repo(s) protect the default branch
  - web
- [ok] **Reviews required and force push blocked** (github): 0 protected repo(s) lack a required review or allow force push
