# Microsoft 365 / Entra ID

`Invoke-T0M365AdminInventory` lists every admin with role, permanence and MFA, and writes the Zero 1 and Zero 2 counts. `Get-T0M365Domain` lists the tenant's domains for discovery (Zero 5). Both are read-only.

## Install

PowerShell 7.4 or later:

```powershell
Install-Module TargetZero, Microsoft.Graph.Authentication -Scope CurrentUser
Import-Module TargetZero
```

Only `Microsoft.Graph.Authentication` is needed; the module calls Graph directly.

## Sign in

### Interactive (default)

Use an account with the **Global Reader** role.

```powershell
$config = Import-T0Config                  # reads targetzero.yaml
Connect-T0M365 -Config $config
```

The first time, an admin must consent to these delegated Microsoft Graph permissions for *Microsoft Graph Command Line Tools*. They are all read-only:

`Directory.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `Application.Read.All`, `Domain.Read.All`

### Unattended

1. Create an app registration and upload a certificate (no client secret).
2. Grant the same permissions as **application** permissions and give admin consent.
3. Put the ids in `targetzero.yaml`:

```yaml
m365:
  tenant_id: contoso.onmicrosoft.com
  client_id: 00000000-0000-0000-0000-000000000000
  certificate_thumbprint: ABCDEF...
```

`Connect-T0M365` then signs in with the certificate.

## Run

```powershell
Invoke-T0M365AdminInventory -Config $config
Get-T0M365Domain -Config $config
```

Output in `output/<date>/`: `1_m365_admins.csv`, `1_m365_admins.summary.json`, `2_m365_mfa.summary.json`, `5_m365_domains.csv`.

## How admins are judged

| Column | Rule |
| --- | --- |
| privileged | The role is listed under `m365` in `privileged_roles.yaml`. |
| permanent | Active with no end date. Without Entra ID P2 (no PIM) every active assignment is permanent. Eligible PIM assignments are listed but not permanent. |
| account_type | `service` for apps (service principals with a role, or with a high-risk Graph application permission from `m365_app_permissions`). Apps count for Zero 1, not Zero 2. |
| mfa_class | From registered methods. FIDO2, passkeys, Windows Hello, platform credential and certificates are *phishing-resistant*; Authenticator and OATH codes are *mfa*; phone (SMS, voice) *does not count*. The **weakest** registered sign-in method counts, because that is the one an attacker will pick, unless a phishing-resistant authentication strength is enforced. |
| mfa_enforced | `Y` when Security Defaults, per-user MFA, or an enabled Conditional Access policy requires MFA for this admin on all apps. A policy with location, platform, risk, client app or device conditions, or MFA OR-ed with another control, leaves gaps: `unknown`. Report-only policies do not count. |
| separate_admin_account | `N` when the admin account has a licence: it is then most likely also used for mail. |
| break_glass | The account is listed under `break_glass.m365` in `targetzero.yaml`. Break-glass accounts are left out of Zero 1, but still need MFA (a FIDO2 key) for Zero 2. |

## Licences

| Feature | Without it |
| --- | --- |
| Entra ID P1 (Conditional Access, registration report, sign-in activity) | Methods are read per user; only Security Defaults and per-user MFA count as enforcement; `last_logon` stays empty. |
| Entra ID P2 (PIM) | All active assignments are permanent. The fix is a shorter list, not time-bound access. |

The licence found is written in the summary notes.

## Not covered yet

- Exchange Online and other workload role groups (e.g. *Organization Management*). List their members in `registers/manual_admins.csv`.
- PIM for Groups eligible membership.
- Azure RBAC (subscription owners): planned for 1.0.

## Making changes (0.3)

Change commands never decide on their own. They read a plan that a person has reviewed, show what they would do, and change something only with `-Apply`. Every applied run writes a log and a rollback plan in `output/<date>/`.

Sign in for changes with an account that holds the needed role (see each command). `-ReadWrite` always uses interactive sign-in, so changes are made by a person, never by the unattended app:

```powershell
Connect-T0M365 -Config $config -ReadWrite
```

### 1. Break-glass accounts first

```powershell
New-T0M365BreakGlassAccount -Config $config            # dry run
New-T0M365BreakGlassAccount -Config $config -Apply
```

Creates two cloud-only Global Administrators on the `onmicrosoft.com` domain (names from `break_glass.m365`), the group `T0-BreakGlass`, and shows each password **once**. It is never written to disk or to the log. Store the passwords offline and register FIDO2 keys on both accounts. Role: Global Administrator, or Privileged Role Administrator plus User Administrator.

### 2. Reduce admin rights

`Invoke-T0M365AdminInventory` also writes `1_m365_role-plan.csv`: one row per role assignment as Entra ID stores it (a group that holds a role is one row). Fill in `action`:

| action | Effect | Needs |
| --- | --- | --- |
| `remove` | Remove the role or the app permission | |
| `make-eligible` | Replace the active assignment with a PIM-eligible one (optional end date in `new_end_date`) | Entra ID P2 |
| `time-bound` | Keep it active until `new_end_date` | Entra ID P2 |
| `make-permanent`, `restore-active`, `restore-eligible`, `restore-app-permission` | Used by rollback plans | |

```powershell
Set-T0M365RoleAssignment -Config $config -PlanPath output/2026-11-19/1_m365_role-plan.csv          # dry run
Set-T0M365RoleAssignment -Config $config -PlanPath output/2026-11-19/1_m365_role-plan.csv -Apply   # asks per change
```

It refuses to touch break-glass accounts and refuses any change that would leave no active Global Administrator. To undo a run: `Set-T0M365RoleAssignment -PlanPath output/<date>/rollback_m365_roles_<time>.csv -Apply`. Role: Privileged Role Administrator.

### 3. Conditional Access for admins

```powershell
New-T0M365AdminCaPolicy -Config $config -Apply            # report-only
New-T0M365AdminCaPolicy -Config $config -Apply -Enable    # enforce, after checking the report
```

Creates *T0 - Admins require phishing-resistant MFA* (privileged roles, all apps, built-in phishing-resistant strength) and *T0 - Block legacy authentication* (all users). Both exclude `T0-BreakGlass`. The directory sync role is left out, because that account cannot do MFA.

`-Enable` first reads the latest admin inventory and refuses while any privileged admin has no phishing-resistant method, because that admin would be locked out. Run `Invoke-T0M365AdminInventory` again after keys are registered. Without Entra ID P1, use `-UseSecurityDefaults` instead. Role: Conditional Access Administrator.
