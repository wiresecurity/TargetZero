# Google Workspace

`targetzero gws admins` lists every admin with role, permanence and MFA, and writes the Zero 1 and Zero 2 counts. `targetzero gws domains` lists your domains for discovery (Zero 5). Both are read-only.

## Install

```bash
pip install 'targetzero[gws]'      # or: pip install -e '.[gws]' from a clone
```

## Credentials

You need a Google Cloud project with the **Admin SDK API** enabled. Then choose one:

### Service account with domain-wide delegation (scheduled runs)

1. Create a service account and a JSON key. Store the key **outside** the repository.
2. In the Admin console, go to *Security > Access and data control > API controls > Domain-wide delegation* and add the service account's client id with these scopes:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
https://www.googleapis.com/auth/admin.directory.domain.readonly
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/admin.reports.usage.readonly
```

3. In `targetzero.yaml`:

```yaml
gws:
  customer_id: my_customer
  admin_subject: reporting-admin@example.com   # an admin with read access to users, roles and reports
  credentials_file: ~/secrets/targetzero-gws.json
```

### OAuth desktop client (small tenants)

Create an OAuth client of type *Desktop app*, download the JSON and set `credentials_file` to it. Leave `admin_subject` empty. A browser opens once; sign in as an admin.

## Run

```bash
targetzero gws admins            # --days 30: how much sign-in history to read
targetzero gws domains
```

## How admins are judged

| Column | Rule |
| --- | --- |
| role / privileged | From role assignments. Super admins without an explicit assignment are added from the user list. A role is privileged when it is a super admin role or listed under `gws` in `privileged_roles.yaml`. |
| permanent | Google Workspace has no general expiry on roles. An assignment is time-bound only when it has a condition on `request.time`. |
| mfa_class | Not enrolled in 2-Step Verification: *none*. Otherwise the second factors the admin **actually used** to sign in during the last `--days` days (login audit): security key or passkey *phishing-resistant*; Google prompt, authenticator, backup codes *mfa*; phone codes *do not count*. The weakest one used counts. Enrolled but no sign-in in the period: *unknown*, which counts until someone signs in. |
| mfa_enforced | 2-Step Verification is enforced for the admin. |
| separate_admin_account | `N` when the admin sent mail on recent days (Gmail usage report, which lags about three days). |

To allow only security keys for admins, put them in a dedicated org unit and set *Allowed methods: Only security key* for that unit in *Security > 2-Step Verification*. This setting cannot be changed through the API.

## Not covered yet

- Roles assigned to **groups** are noted but not expanded: list those members in `registers/manual_admins.csv`.

## Making changes (0.3)

`targetzero gws admins` also writes `1_gws_role-plan.csv`. Fill in `action`:

| action | Effect |
| --- | --- |
| `revoke` | Remove the role. A super admin without an explicit assignment loses super admin status. |
| `move-ou` | Move the admin into `target_org_unit`, e.g. `/Admins` (where you enforce security keys) |
| `restore-role`, `restore-super-admin` | Used by rollback plans |

```bash
targetzero gws apply output/2026-11-19/1_gws_role-plan.csv            # dry run
targetzero gws apply output/2026-11-19/1_gws_role-plan.csv --apply    # asks for confirmation
```

It never changes break-glass accounts and refuses to leave fewer than two super admins. Each applied run writes `rollback_gws_roles_<time>.csv`; apply it the same way to undo.

Changes need two more scopes. Add them to the domain-wide delegation entry only while you make changes, and remove them afterwards:

```
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/admin.directory.rolemanagement
```
