# Rights needed per tool

This page lists, for every TargetZero command, which rights it needs: on the platform it reads or changes, on your own computer, and on the network. The [step-by-step guide](guide.md) repeats the relevant line at each step.

Principles:

- **Measuring needs read rights only.** Use a read-only account or role for it, even when you also have admin rights.
- **Changing needs a person.** Change commands always sign in interactively with your own admin account, never with a stored key or app.
- **Give rights for the time you need them.** Remove change permissions (Google scopes, PIM activations) when the change round is over.

---

## Your own computer

| What | Rights needed |
| --- | --- |
| Python from the **Microsoft Store** (Windows) | None: installs for your user only. |
| Python from **python.org** (Windows) | None for *Install Now*. Untick *Use admin privileges when installing py.exe* if you are not a local administrator. |
| Python from **python.org** (Mac) | Your Mac password (administrator of the Mac). |
| PowerShell 7 from the **Microsoft Store** (Windows) | None. |
| PowerShell 7 with **winget** or the **.msi** (Windows), or the **.pkg** (Mac) | Local administrator. |
| `py -m pip install targetzero`, `Install-Module … -Scope CurrentUser` | None: both install for your user only. |
| `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (Windows) | None, unless your organisation fixes the policy centrally (then ask your IT provider). |
| nmap (optional, for `external scan`) | Local administrator to install. Running it needs no special rights: TargetZero uses a normal connect scan (`-sT`). |
| Running any TargetZero command | None. TargetZero needs no administrator rights on your computer. |

---

## Microsoft 365 / Entra ID (PowerShell)

All commands use Microsoft Graph. Graph checks two things: the **permission** the sign-in has (a *scope*, approved once for the organisation), and the **Entra ID role** of the person who signs in. Both must allow the action.

### Approving the permissions (once)

The first `Connect-T0M365` asks Microsoft to approve ("consent to") permissions for the app *Microsoft Graph Command Line Tools*. This is needed **once per organisation** for the read set and **once more** for the change set (`-ReadWrite`).

| Who can approve | Global Administrator or Privileged Role Administrator |
| --- | --- |

| Set | Graph permissions (delegated) | Read or change |
| --- | --- | --- |
| Read (`Connect-T0M365`) | `Directory.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `Application.Read.All`, `Domain.Read.All` | read only |
| Change (`Connect-T0M365 -ReadWrite`) | the read set, plus `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `User.ReadWrite.All`, `Group.ReadWrite.All` | change |

You can check and revoke what was approved in the Entra admin center: *Enterprise applications > Microsoft Graph Command Line Tools > Permissions*.

### Per command

| Command | Sign in with | Entra ID role of the person signing in | Licence notes |
| --- | --- | --- | --- |
| `Invoke-T0M365AdminInventory` | `Connect-T0M365` | **Global Reader** | P1 adds Conditional Access, sign-in dates and the registration report; P2 adds PIM. Without them the count still works, with notes. |
| `Get-T0M365Domain` | `Connect-T0M365` | Global Reader | none |
| `New-T0M365BreakGlassAccount` | `Connect-T0M365 -ReadWrite` | **Global Administrator**, or Privileged Role Administrator **and** User Administrator | none |
| `Set-T0M365RoleAssignment` | `Connect-T0M365 -ReadWrite` | **Privileged Role Administrator** | `make-eligible` and `time-bound` need Entra ID P2 |
| `New-T0M365AdminCaPolicy` | `Connect-T0M365 -ReadWrite` | **Conditional Access Administrator** (or Security Administrator) | Entra ID P1; without it only `-UseSecurityDefaults` |

With PIM (Entra ID P2), **activate** the role for the duration of the work before you sign in. A role that is only *eligible* does not count until it is activated.

### Unattended runs (optional)

For a scheduled count without a person: an app registration with a **certificate** (no client secret), the read set above granted as **application** permissions, and admin consent by a Global Administrator or Privileged Role Administrator. Put `tenant_id`, `client_id` and `certificate_thumbprint` under `m365:` in `targetzero.yaml`. Only the read commands use it; `-ReadWrite` always signs in as a person.

---

## Google Workspace (Python)

### One-time setup in Google Cloud

| Step | Rights needed |
| --- | --- |
| Create a Google Cloud project and enable the **Admin SDK API** | A Google account allowed to create projects in your organisation (by default every user; your organisation may restrict it). |
| OAuth consent screen of type **Internal** | The project must belong to your Workspace organisation. |
| Domain-wide delegation for a service account (only for the service account method) | **Super admin** in the Admin console. |

### Per command

| Command | Google scopes (OAuth) | Admin account that signs in (or `admin_subject`) |
| --- | --- | --- |
| `gws admins` | `admin.directory.user.readonly`, `admin.directory.rolemanagement.readonly`, `admin.reports.audit.readonly`, `admin.reports.usage.readonly` | **Super admin** is simplest. A custom admin role works when it can read users, admin roles and reports. |
| `gws domains` | `admin.directory.domain.readonly` | Same account. |
| `gws apply` | adds `admin.directory.user` and `admin.directory.rolemanagement` | **Super admin**: only a super admin can take away or give back super admin rights. |

All scopes start with `https://www.googleapis.com/auth/`. With the desktop sign-in key, the browser asks you to allow them at each run; nothing is stored. With a service account, add the change scopes to its domain-wide delegation **only** during a change round and remove them afterwards.

---

## Firewalls and other devices (Python)

TargetZero itself needs **no rights on the device** for firewalls: it reads an export file. The person who **makes the export** needs these rights:

| Device | Export rights | TargetZero needs |
| --- | --- | --- |
| Fortinet FortiGate | An admin account allowed to back up the configuration. A `super_admin` account makes a complete backup; a more limited profile can leave parts out. | Read access to the file. |
| Palo Alto Networks (PAN-OS) | `superuser`, or an admin role allowed to export configurations (*Device > Setup > Operations*). | Read access to the file. |
| Cisco ASA | Privilege level 15 for `show running-config`. | Read access to the file. |

Two collectors log in live, **read-only**:

| Device | Account to create | Notes |
| --- | --- | --- |
| Dell iDRAC, HPE iLO, other Redfish cards (`vendors redfish`) | A local account with the **read-only** role (iDRAC: *Read Only*; iLO: only the *Login* privilege). | Network access to the card's HTTPS port (443) from your computer. If the account list comes back with only your own account, that card hides other accounts from read-only users: use an operator account there, or list the card's admins in `registers/manual_admins.csv`. |
| VMware vCenter / ESXi (`vendors vsphere`) | A user with the built-in **Read-only** role on the **vCenter root object**, with *Propagate to children* ticked. | Network access to vCenter on 443. |

Passwords are read from environment variables (`TARGETZERO_REDFISH_USER` / `_PASSWORD`, `TARGETZERO_VSPHERE_USER` / `_PASSWORD`), never from the settings file.

`registers manual-admins` needs no rights: you fill in the list by hand. Getting the information may need admin access to each system.

---

## Internet checks (Python)

These need no account anywhere, but they do need **permission** and **network access**.

| Command | Permission you need | Network |
| --- | --- | --- |
| `external discover` | None: it reads public sources (DNS, certificate logs). For `--zone-file`: someone with access to your DNS provider exports the zone. | DNS, and HTTPS to `crt.sh`. |
| `external scan --authorised` | **Written permission to scan every address** in `scope.ip_ranges`: you own them, or the owner (internet provider, hosting or cloud provider, landlord) allows it. Read your provider's terms; most allow scanning your own addresses, some ask you to notify them. | Outgoing TCP to your addresses, from **outside** your network. With `--internetdb`: HTTPS to `internetdb.shodan.io`. |
| `external waf` | None for the basic check (public DNS and one web request per site). With `--authorised`: the same permission as `scan`, for the origin addresses in `registers/origins.csv`. | DNS, HTTPS/HTTP to your sites. |
| `external dangling-dns` | None: DNS lookups and one web request per name. Deleting the records it finds needs access to your DNS provider. | DNS, HTTPS/HTTP. |
| `external enrich` | None: one web request per site in scope. | HTTPS/HTTP to your sites, HTTPS to `endoflife.date`. |
| `external kev` | None. An NVD API key (free, optional) makes it faster: set `NVD_API_KEY`. | HTTPS to `www.cisa.gov` and `services.nvd.nist.gov`. |

If a company proxy or firewall blocks these sites, the command reports the check as **incomplete**. Ask your IT provider to allow them, or run from another connection.

Tell your IT or internet provider before you run `external scan`: their intrusion detection may raise an alarm, and that is a good test of target 3.

---

## Registers and reporting (Python)

`init`, `scorecard`, `validate`, `registers inventory`, `registers findings` and `registers manual-admins` only read and write files in your working folder. They need no account and no network.

Signing exceptions in `registers/exceptions.csv` needs a **manager with the authority to accept the risk** (see the guide, section 9). That is an organisational right, not a technical one, and it is the one most often missing.
