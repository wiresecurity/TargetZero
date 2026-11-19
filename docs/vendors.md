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

## Cisco ASA

Export: `show running-config` saved to a text file (or *File > Show Running Configuration* in ASDM).

| What | How it is judged |
| --- | --- |
| Admins | `username` lines; VPN-only users (`service-type remote-access`) are skipped. Privilege 15 is privileged. |
| MFA | Console login (`aaa authentication ssh/http console`) through a RADIUS/TACACS+ group: *unknown*, check MFA on that server; the group is listed as one "remote admins" account. LOCAL only: *none*. |
| Management exposure | `ssh`, `http` (with `http server enable`) or `telnet` allowed on an interface with security-level 0 or named like outside, internet or wan. The reason shows from where. |
| Version | `ASA Version` line. |

Firepower Threat Defense managed by FMC is not covered yet.

## Server management cards (Redfish: Dell iDRAC, HPE iLO, others)

Live and read-only. Create a read-only account on each card.

```bash
export TARGETZERO_REDFISH_USER=readonly TARGETZERO_REDFISH_PASSWORD=...
targetzero vendors redfish --host idrac-01.example.com --host ilo-02.example.com --ca-bundle bmc-ca.pem
```

Lists the local accounts and their role (*Administrator* is privileged), whether multi-factor authentication (RSA SecurID, Google or Microsoft Authenticator, client certificates) is enabled, and the firmware version. Whether the card can be reached from the internet is checked by `external scan` (ports 443 and 623). `--insecure` skips certificate checks; use it only on your own management network.

## VMware vSphere (vCenter, ESXi)

Live and read-only: `pip install 'targetzero[vsphere]'`.

```bash
export TARGETZERO_VSPHERE_USER='readonly@vsphere.local' TARGETZERO_VSPHERE_PASSWORD=...
targetzero vendors vsphere --host vcenter.example.com
targetzero vendors vsphere --host vcenter.example.com --mfa-via-idp
```

Lists every permission (principal, role, object), with *Admin* as privileged, and the product version for the vulnerability check. MFA depends on the identity source (vCenter SSO, Active Directory, or identity federation with Entra ID, ADFS or Okta), which the API does not show. All admins are *unknown* until you confirm MFA is enforced there and pass `--mfa-via-idp`.

## Not yet: SonicWall and Veeam

Both are on the tier 1 list. They will be added once they can be tested against real (scrubbed) exports: the SonicWall `.exp` settings format and the Veeam Backup & Replication REST API for users and roles. Until then, put their admins in `registers/manual_admins.csv`. Sample files are welcome; see CONTRIBUTING.md.

## Other systems

For devices without a collector (other firewalls, hypervisors, backup consoles, iDRAC/iLO, SaaS), fill in `registers/manual_admins.csv` and count it:

```bash
targetzero registers manual-admins
```
