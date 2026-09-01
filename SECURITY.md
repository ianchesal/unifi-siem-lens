# Security Policy

## Supported Versions

Only the latest release is supported with security fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately via [GitHub's private vulnerability reporting](https://github.com/ianchesal/unifi-siem-lens/security/advisories/new).

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested remediation, if you have one

I'll acknowledge receipt within 7 days and aim to release a fix within 30 days for confirmed issues.

## Scope

This project runs on a private homelab network and is not intended for
public internet exposure. Unlike its sibling projects, **the REST API and
MCP endpoint have no authentication** — this is a deliberate design choice
for a single-user LAN dashboard, not an oversight. The server binds to
`127.0.0.1` by default for exactly this reason; only widen `HOST` (or a
Docker port publish) deliberately, and never expose port 3100 to the
internet. This service also opens the sibling `unifi-siem-sink` project's
database **read-only** and never writes to it.
