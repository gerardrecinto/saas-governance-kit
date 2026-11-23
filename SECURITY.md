# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's "Report a vulnerability"
button on the Security tab of this repository. Do not open a public issue for security problems.
Expect an acknowledgement within a few days.

## Scope and caveats

This is a portfolio and reference project. It has only been exercised against local fixtures and
a locally generated test IdP. Review the code before using it against production identity systems.

- Never commit tokens, signing secrets, private keys or IdP metadata containing secrets.
- The test keys generated in the test suite are ephemeral and are not written to the repository.
- The SCIM server uses a single static bearer token and an optional JSON file store. Put it behind
  TLS and a real secret store before any shared use.
