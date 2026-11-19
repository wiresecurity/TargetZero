# Vendor collectors

Collectors read a **configuration export**, so TargetZero never needs credentials for your firewall. Pass every device of one vendor in a single run; a second run replaces the first.

```bash
targetzero vendors fortigate backups/fgt-hq.conf backups/fgt-branch.conf
targetzero vendors panos backups/pa-edge-running-config.xml
```

Each run writes the admin records and Zero 1 / Zero 2 summaries, a Zero 4 summary for management access on internet-facing interfaces, and `devices_<vendor>.csv` with the firmware version, which `targetzero external kev` uses.

Config backups contain password hashes and keys. Keep them out of the repository and delete them when you are done.

## Fortinet FortiGate

Export: *System > Configuration > Backup* (unencrypted), or `execute backup config`.

| What | How it is judged |
| --- | --- |
| Privileged | Admin profile `super_admin` or `prof_admin`. |
| MFA | `two-factor fortitoken` / `fortitoken-cloud`: *mfa*. `email` / `sms`: *does not count*. Remote authentication (RADIUS, LDAP, TACACS+) or SAML SSO admins: *unknown*, check MFA on that server. Otherwise *none*. |
| Trusted hosts | Listed in the notes; "no trusted hosts set" means the admin can log in from anywhere. |
| Management exposure | An interface with role `wan` (or named `wan*`) that allows `http`, `https`, `ssh`, `telnet`, `snmp` or `fgfm`. |
| Version | From the `#config-version` header. |

## Palo Alto Networks PAN-OS

Export: *Device > Setup > Operations > Export named configuration snapshot*, `running-config.xml`.

| What | How it is judged |
| --- | --- |
| Privileged | Role `superuser`, `deviceadmin` or `vsysadmin`. |
| MFA | Client certificate only: *phishing-resistant*. Authentication profile with multi-factor authentication: *mfa*. Local password or local-database profile: *none*. RADIUS, LDAP, SAML or TACACS+ profile: *unknown*, check MFA on that server. |
| Management exposure | An interface management profile with `https`, `http`, `ssh`, `telnet` or `snmp` on an interface in a zone named like untrust, outside, internet, wan, external or public. |
| Version | `detail-version` of the config. |

Admins managed only by Panorama are not in the device config; a note says so.

## Other systems

For devices without a collector (other firewalls, hypervisors, backup consoles, iDRAC/iLO, SaaS), fill in `registers/manual_admins.csv` and count it:

```bash
targetzero registers manual-admins
```
