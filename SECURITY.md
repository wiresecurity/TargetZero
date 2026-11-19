# Security policy

TargetZero handles admin inventories and configuration of production tenants and devices. We take reports about it seriously.

## Reporting a vulnerability

Do **not** open a public issue. Report privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting).

Please include the affected script or module, the version or commit, and the steps to reproduce.

| Step | Target |
| --- | --- |
| Acknowledgement | 3 working days |
| First assessment | 10 working days |
| Fix or mitigation for high and critical issues | 30 days |

We credit reporters in the release notes unless you ask us not to.

## Supported versions

Only the latest minor release receives security fixes.

## Scope

In scope: code in this repository, the published PowerShell module and Python package, and the release workflow.

Out of scope: vulnerabilities in Microsoft 365, Google Workspace or vendor products themselves. Report those to the vendor.

## How TargetZero protects your data

- No telemetry. Scripts only contact the platform APIs, your own systems, and the public reference sources listed in the README.
- Inventory scripts are read-only. Change scripts run as a dry run unless explicitly told to apply.
- Credentials are never written to config or output files.
