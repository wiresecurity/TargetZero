# TargetZero step by step

This guide is for the person who runs the Target 0 campaign in their organisation: someone who **has the admin rights** on the systems involved, but is **not an IT specialist**. You need no programming knowledge. You will copy commands from this guide, paste them, and read what comes back.

What this guide gives you:

- **Part 1**: install TargetZero and prepare it (once, about 1 to 2 hours).
- **Part 2**: every tool, one by one, always in the same five steps: *what it does*, *rights you need*, *run it*, *what you get*, *what to do with it*.
- **Part 3**: the order to use them in during the 15 days, the weekly report, and what to do when something goes wrong.

The rights for every tool are collected in one place in [permissions.md](permissions.md). This guide repeats the line that matters at each step.

> Read Part 1 and the **safety rules** (section 2) completely before you start. TargetZero looks at, and can change, the most sensitive parts of your organisation: your administrator accounts and what you expose to the internet.

**Contents**

Part 1: Prepare

1. [What TargetZero does](#1-what-targetzero-does)
2. [Safety rules](#2-safety-rules)
3. [Install the software](#3-install-the-software)
4. [Create your working folder and settings](#4-create-your-working-folder-and-settings)
5. [How every tool works](#5-how-every-tool-works)

Part 2: The tools

6. [Microsoft 365](#6-microsoft-365)
7. [Google Workspace](#7-google-workspace)
8. [Firewalls, servers and other systems](#8-firewalls-servers-and-other-systems)
9. [Your internet perimeter](#9-your-internet-perimeter)
10. [Registers, exceptions and the scorecard](#10-registers-exceptions-and-the-scorecard)

Part 3: Run the campaign

11. [The 15 days: what to run when](#11-the-15-days-what-to-run-when)
12. [When something goes wrong](#12-when-something-goes-wrong)
13. [Words used in this guide](#13-words-used-in-this-guide)

---

# Part 1: Prepare

## 1. What TargetZero does

The Target 0 campaign (see [TargetZero.pdf](../TargetZero.pdf)) asks you to bring seven numbers to zero within 15 days. TargetZero **counts** those numbers, **helps you fix** what it finds, and builds the **scorecard** for management.

| Target | What is counted | Tools (section) |
| --- | --- | --- |
| 1 | Admins with full, permanent access | Microsoft 365 (6), Google Workspace (7), firewalls and servers (8) |
| 2 | Admins without MFA that counts | same as target 1 |
| 3 | Admins not monitored | by hand (10.4) |
| 4 | Public addresses not behind a firewall, WAF or CDN | port scan, WAF check, firewall exports (9, 8) |
| 5 | Public addresses and domains without inventory | discovery, inventory, forgotten DNS records (9) |
| 6 | Known exploited vulnerabilities past their deadline | vulnerability check (9.6) |
| 7 | Internet-facing apps without a tested recovery page | by hand (10.4) |

TargetZero has two parts:

- A **PowerShell module** for Microsoft 365. You run its commands in *PowerShell 7*. They look like `Invoke-T0M365AdminInventory`.
- A **Python program** for everything else. You run it in any terminal. Its commands look like `py -m targetzero external scan`.

What it does **not** do: it does not watch your systems day and night, it does not send alerts, and it does not install anything on your servers. It runs on your computer when you start it, and stops when it is done.

---

## 2. Safety rules

1. **Every change command first shows what it *would* do, and changes nothing.** Only when you add `-Apply` (PowerShell) or `--apply` (Python) does it change something. Always run without it first, read the result, and only then run again with it.
2. **Make changes only when you can deal with surprises.** Not on a Friday evening. Preferably with a second person, or your IT provider, available.
3. **Create the emergency (break-glass) accounts before you remove any admin rights** (6.4). They are your way back in if you lock yourself out.
4. **Never switch on the MFA rule for admins before every admin has a security key or passkey.** TargetZero refuses when it sees an admin without one, but check yourself too.
5. **Keep the results private.** The `output` and `registers` folders list your admins and your weak spots. Do not e-mail them around, do not put them in OneDrive, SharePoint, Dropbox or Google Drive, do not upload them anywhere.
6. **Never scan addresses that are not yours.** The internet scan only checks what you list in the settings file. List only addresses your organisation owns or rents, with permission of whoever manages them. Scanning other people's systems can be illegal.
7. **Run the internet scan from outside your office network**: a home connection or a phone hotspot. From inside the office you see your own network, not what attackers see.
8. **Firewall export files contain secrets** (password hashes, keys). Keep them only in your working folder, and delete them when the campaign is done.
9. **Keep the rollback files.** The change commands write a file named `rollback_…csv` that records how to undo the change. Do not delete them during the campaign.
10. **Use the lowest rights that do the job.** Measure with a read-only account (Global Reader, a read-only device account). Use your full admin account only for the change steps.
11. **When in doubt, stop and ask.** Nothing in this campaign is so urgent that a wrong change is better than a day's delay. Your IT provider, or Wire Security, can help.

---

## 3. Install the software

You install Python and TargetZero. For Microsoft 365 you also install PowerShell 7 and the TargetZero module.

**Rights you need:** none on your computer if you use the Microsoft Store (Windows). With the Mac installers, your Mac password. Details: [permissions.md, Your own computer](permissions.md#your-own-computer).

### 3.1 Open a terminal

A terminal is a window where you type commands. Copy a command from this guide, paste it, and press **Enter**.

- **Windows:** press the Windows key, type `Terminal`, and open **Terminal** (or **Windows PowerShell**).
- **Mac:** press **Cmd + Space**, type `Terminal`, press **Enter**.

Tips:

- Folders like `C:\Target0\Acme` are examples. Replace them with your own.
- Windows writes folders with `\`, a Mac with `/`. The examples use Windows style; on a Mac write `exports/fw-office.conf` instead of `exports\fw-office.conf`.
- In this guide, Python commands start with `py` (Windows). **On a Mac, type `python3` wherever the guide says `py`.**

### 3.2 Install Python

- **Windows:** open the **Microsoft Store**, search for **Python 3.13** (or newer), and click **Get**. Or download it from <https://www.python.org/downloads/>; in that installer, tick **Add python.exe to PATH** at the bottom of the first screen.
- **Mac:** download Python 3.13 (or newer) from <https://www.python.org/downloads/>, run the installer, then open the *Python 3.x* folder in Applications and double-click *Install Certificates.command*.

Close the terminal and open a new one. Check:

```
py --version
```

(Mac: `python3 --version`.) It must say **3.11 or higher**.

**Mac: if it says `Python 3.9`**, the Mac still uses Apple's built-in Python. Open a new terminal; if it still says 3.9, see the pipx note in 3.4.

### 3.3 Install PowerShell 7 (Microsoft 365 only)

Windows has an older *Windows PowerShell 5*. TargetZero needs **PowerShell 7**.

- **Windows:** Microsoft Store, search **PowerShell**, install it.
- **Mac:** download the `.pkg` for macOS from <https://aka.ms/powershell-release?tag=lts> and install it.

From now on, "open PowerShell 7" means: start the app called **PowerShell** (Windows: *PowerShell 7* in the Start menu; Mac: type `pwsh` in Terminal). Check:

```powershell
$PSVersionTable.PSVersion
```

It must say 7.4 or higher. Then, in PowerShell 7:

```powershell
Install-Module TargetZero, Microsoft.Graph.Authentication -Scope CurrentUser
```

Answer **Y** if it asks whether you trust *PSGallery*. **Windows only**, allow downloaded scripts to run for your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 3.4 Install TargetZero (Python)

In a terminal:

```
py -m pip install "targetzero[gws]"
```

`[gws]` adds Google Workspace support. Leave it out if you do not use Google Workspace. With VMware vSphere, use `"targetzero[gws,vsphere]"`. Check:

```
py -m targetzero --version
```

> **Mac with Homebrew**, or an error `externally-managed-environment`: use pipx.
>
> ```
> brew install pipx
> pipx ensurepath
> pipx install "targetzero[gws]"
> ```
>
> Open a new terminal, and type `targetzero` wherever this guide says `py -m targetzero`.

### 3.5 Keep it up to date

New versions fix problems and add checks. Update both parts, and keep them on the same version:

```
py -m pip install --upgrade "targetzero[gws]"
```

```powershell
Update-Module TargetZero
```

After `Update-Module`, close PowerShell and open it again.

---

## 4. Create your working folder and settings

### 4.1 The working folder

All settings, lists and results live in one **working folder** per organisation, on your own computer. Not in OneDrive, SharePoint, Dropbox or Google Drive.

```
mkdir C:\Target0\Acme
cd C:\Target0\Acme
py -m targetzero init
```

(Mac: `mkdir -p ~/Target0/Acme`, `cd ~/Target0/Acme`, `python3 -m targetzero init`.)

This creates:

| File or folder | What it is |
| --- | --- |
| `targetzero.yaml` | Your settings (next step). |
| `privileged_roles.yaml` | Which admin roles count as "full admin". The default list is fine to start. |
| `registers\` | Lists you keep up to date by hand, in Excel: admins of other systems, your inventory, vulnerabilities, exceptions, alert tests, recovery pages. |
| `output\` | Created at the first run. One sub-folder per day with all results. |

**Every time you use TargetZero, first go to this folder** with `cd C:\Target0\Acme`. TargetZero reads `targetzero.yaml` from the folder you are in.

### 4.2 The settings file

Open `targetzero.yaml` with **Notepad** (Windows) or **TextEdit** (Mac: *Format > Make Plain Text*). Not with Word. Change these parts:

```yaml
organisation: Acme Ltd

owners:
  "1": "Jane Doe, office manager"
  "2": "Jane Doe, office manager"
  "3": "IT provider ABC"
  "4": "Jane Doe, office manager"
  "5": "Jane Doe, office manager"
  "6": "IT provider ABC"
  "7": "Application owners"

break_glass:
  m365:
    - bg-admin-01@acme.onmicrosoft.com
    - bg-admin-02@acme.onmicrosoft.com
  gws:
    - bg-admin-01@acme.com
    - bg-admin-02@acme.com

scope:
  domains:
    - acme.com
  ip_ranges:
    - 203.0.113.16/29
```

| Setting | What to fill in |
| --- | --- |
| `organisation` | Your organisation's name. |
| `owners` | Who is responsible for each of the seven targets. It appears on the scorecard. |
| `break_glass` | Your two emergency admin accounts per platform. If you do not have them yet, choose the names now; TargetZero creates them for Microsoft 365 (6.4). Microsoft 365 names must end in `.onmicrosoft.com` (find yours in the Microsoft 365 admin center, *Settings > Domains*). Remove the platform you do not use. |
| `scope` → `domains` | Your own domain names. |
| `scope` → `ip_ranges` | Your public internet addresses. Ask your internet or IT provider: "Which fixed public IP addresses do we have?" One address is written as `203.0.113.17/32`. **Only addresses you own or rent.** |

Keep the spaces at the start of lines exactly as shown (spaces, not tabs), and the quotes around `"1"` to `"7"`. Check the file:

```
py -m targetzero scorecard
```

A mistake is reported with the setting's name. If all is well you see seven rows reading **no data**: correct, nothing has been measured yet.

---

## 5. How every tool works

All tools follow the same pattern. Learn it once.

### 5.1 Starting a session

**Python tools:** open a terminal, then:

```
cd C:\Target0\Acme
py -m targetzero <command>
```

**Microsoft 365 tools:** open PowerShell 7, then these three lines **every time** you open a new window:

```powershell
cd C:\Target0\Acme
Import-Module TargetZero
$config = Import-T0Config
```

### 5.2 What you see on screen

Each counting tool ends with a short summary per target:

```
Zero 1 m365/admins: 4
Zero 2 m365/mfa: 2
  note: Entra ID licence: P1
```

- The number is the count for that target, from this source.
- `note:` lines explain what was seen, or not. **Always read them.**
- `(incomplete)` after a number means TargetZero could not see everything: a missing licence or permission, or a site that did not answer. Do not report that number until the note is resolved.

The PowerShell commands print the paths of the files they wrote instead.

### 5.3 Where the results are

Everything goes into `output\<date>\`, e.g. `output\2026-11-20\`. Running a tool again on the same day replaces that day's files. Earlier days are kept, so you can compare.

| File type | What it is | Open with |
| --- | --- | --- |
| `<target>_<source>_<name>.csv` | The details: one row per admin, open port, website, and so on. | Excel |
| `….summary.json` | The count that goes on the scorecard, and the notes. | Notepad (you rarely need to) |
| `…_role-plan.csv` | A list of changes for you to fill in (6.5, 7.4). | Excel |
| `dryrun_…json`, `changes_…json` | The log of a test run or a real change. | Notepad |
| `rollback_…csv` | The plan that undoes a change. Keep it. | Excel |

The first number of each file name is the target it belongs to: `1_m365_admins.csv` is target 1, `4_external_exposure.csv` is target 4.

### 5.4 Change commands: test, check, apply, undo

Change commands (6.4, 6.5, 6.6, 7.4) always work in four steps:

1. **Test.** Run without `-Apply` / `--apply`. Each line says `dry-run` (would do it) or `refused` (will not do it, and why). Nothing changes.
2. **Check.** Read every line. Ask yourself: is this what I want, and is the emergency access in place?
3. **Apply.** Run the same command with `-Apply` / `--apply`. It asks for confirmation per change. Each line then says `applied`, `failed` (with the reason) or `skipped`.
4. **Undo, if needed.**
   - Role changes (6.5, 7.4): run the same command with the `rollback_…csv` file it wrote as the plan, with `-Apply` / `--apply`.
   - MFA rules (6.6): the rollback file lists each rule's previous state. Set the rule back, or delete it, in the Entra admin center.
   - Emergency accounts (6.4): nothing to undo automatically. Delete the accounts in the admin center if you really need to.

### 5.5 Working with the CSV files in Excel

- With Belgian, Dutch, French or German regional settings, Excel may show a whole row in one column. Open the file through **Data > From Text/CSV**, delimiter *Comma*, instead of double-clicking it.
- Save registers and plans with **File > Save As > CSV UTF-8**. Excel may use semicolons; TargetZero reads both.
- Excel turns dates like `2026-11-20` into `20/11/2026`. TargetZero needs `2026-11-20`. Set date columns to **Text** before typing.
- Use exactly the allowed values: `Y` / `N`, not `yes` / `no`.
- After editing a register, check it: `py -m targetzero validate registers\inventory.csv` (or the file you edited).

---

# Part 2: The tools

## 6. Microsoft 365

All commands in this section run in **PowerShell 7**, after the three lines from 5.1.

### 6.1 Sign in

**What it does:** connects PowerShell to your Microsoft 365 tenant.

**Rights you need:**

- To count: an account with the **Global Reader** role.
- **The first time only:** a **Global Administrator** (or Privileged Role Administrator) approves the permissions for the organisation. TargetZero asks only read permissions for counting. The change commands (6.4 to 6.6) ask a second set, approved once more the first time you use `-ReadWrite`.

Full list: [permissions.md, Microsoft 365](permissions.md#microsoft-365--entra-id-powershell).

**Run it:**

```powershell
Connect-T0M365 -Config $config
```

A browser window opens. Sign in. The first time, Microsoft shows the permissions for *Microsoft Graph Command Line Tools*; a Global Administrator ticks *Consent on behalf of your organization* and accepts.

For the change commands, sign in again with your admin account and the change permissions:

```powershell
Connect-T0M365 -Config $config -ReadWrite
```

With PIM (Entra ID P2): **activate** your admin role first, then sign in.

### 6.2 Count admins and their MFA (targets 1 and 2)

**What it does:** lists every account and app with an admin role in Microsoft 365 / Entra ID, and for each one: which role, whether it is permanent, which sign-in methods it has, and whether MFA is enforced. Reads only.

**Rights you need:** Global Reader (6.1).

**Run it:**

```powershell
Invoke-T0M365AdminInventory -Config $config
```

It takes a few seconds to a few minutes, depending on the number of admins.

**What you get:**

| File | Content |
| --- | --- |
| `1_m365_admins.csv` | One row per admin and role. |
| `1_m365_role-plan.csv` | One row per role assignment, with an empty `action` column. You use it in 6.5. |
| `1_m365_admins.summary.json` | Target 1 count: admins with permanent full rights (emergency accounts not counted). |
| `2_m365_mfa.summary.json` | Target 2 count: admins whose MFA does not count, or is not enforced. |

How to read `1_m365_admins.csv`:

| Column | Meaning | Goal |
| --- | --- | --- |
| `privileged` | `Y` when the role counts as full admin (list in `privileged_roles.yaml`). | |
| `permanent` | `Y` when the role is always active, with no end date. | `N` for every privileged admin, except the two emergency accounts. |
| `mfa_class` | The **weakest** sign-in method the person has registered: `phishing-resistant` (security key, passkey, Windows Hello), `mfa` (authenticator app), `does-not-count` (SMS, voice call), `none`, `unknown`. | `phishing-resistant` |
| `mfa_enforced` | `Y` when a rule forces MFA for this admin; `unknown` when a rule has exceptions TargetZero cannot judge. | `Y` |
| `separate_admin_account` | `N` when the admin account has a licence: it is then probably also used for mail and browsing. | `Y` |
| `account_type` | `service` for apps. Apps count for target 1 only. | |
| `notes` | Plain-language details: via which group, which rule enforces MFA, synced from on-premises, account disabled… | Read them. |

**What to do with it:**

1. Read the list with someone who knows the organisation. For each admin: does this person still need this role? Is a smaller role enough (e.g. *User Administrator* instead of *Global Administrator*)?
2. Mark your decisions in `1_m365_role-plan.csv` (6.5).
3. Admins with `mfa_class` other than `phishing-resistant`: give them a security key or passkey (6.6, step 1).
4. Apps (`(app)` in the account name) with high-risk permissions: ask the supplier or your IT provider whether the app still needs them. Unused apps can be removed with the role plan.
5. A row whose account is a long code (an object id) with the note *user object not found*: a deleted user still holds a role. Remove that assignment (6.5).
6. Run this command again after every change round, and before every report.

### 6.3 List your domains (target 5)

**What it does:** lists the domains registered in your tenant, as a starting point for the internet discovery (9.1). Reads only.

**Rights you need:** Global Reader.

**Run it:**

```powershell
Get-T0M365Domain -Config $config
```

**What you get:** `5_m365_domains.csv`. **What to do with it:** nothing by hand. Run the discovery (9.1) on the **same day**: it picks this file up automatically.

### 6.4 Create the emergency accounts (before any other change)

**What it does:** creates two emergency ("break-glass") Global Administrator accounts on your `onmicrosoft.com` domain, with a 64-character random password, and puts them in a group `T0-BreakGlass` that the MFA rules (6.6) exclude. Accounts that already exist are left alone.

**Rights you need:** `Connect-T0M365 -ReadWrite` as **Global Administrator** (or Privileged Role Administrator plus User Administrator).

**Run it:**

```powershell
New-T0M365BreakGlassAccount -Config $config            # test
New-T0M365BreakGlassAccount -Config $config -Apply     # create
```

**What you get:** on screen, **each password once**. It is not stored anywhere, not even in the log. In the output folder: `changes_m365_breakglass_….json`, the log of what was created.

**What to do with it:**

1. Write down or print the passwords **immediately**. Store them in a safe. Make sure two people know where.
2. Sign in once with each account, at <https://mysignins.microsoft.com/security-info>, and register **two security keys** (FIDO2, e.g. YubiKey) per account. Store the keys with the passwords.
3. Check that `break_glass.m365` in `targetzero.yaml` lists exactly these two accounts.
4. Ask your IT provider to make sure someone is warned whenever these accounts sign in (target 3).

### 6.5 Remove or limit admin rights (target 1)

**What it does:** carries out the decisions you wrote in the role plan: remove a role, make it *eligible* (switched on only when needed), or give it an end date.

**Rights you need:** `Connect-T0M365 -ReadWrite` as **Privileged Role Administrator** (or Global Administrator). `make-eligible` and `time-bound` need the Entra ID P2 licence.

**Prepare the plan:** open `output\<date>\1_m365_role-plan.csv` from the latest count (6.2) in Excel. Fill in the `action` column **only** on rows you want to change; leave all other rows empty.

| `action` | Effect | Extra column |
| --- | --- | --- |
| `remove` | The role, or the app permission, is taken away. | |
| `make-eligible` | The person keeps the role but must switch it on when needed (PIM). | optional `new_end_date` |
| `time-bound` | The role stays active until a date, then ends. | `new_end_date`, e.g. `2026-12-31` |

Save as CSV UTF-8.

**Run it:**

```powershell
Set-T0M365RoleAssignment -Config $config -PlanPath output\2026-11-20\1_m365_role-plan.csv          # test
Set-T0M365RoleAssignment -Config $config -PlanPath output\2026-11-20\1_m365_role-plan.csv -Apply   # change
```

**What you get:** one line per changed row: `dry-run`, `refused` (with the reason), `applied` or `failed`. TargetZero refuses to touch the emergency accounts, and refuses any change that would leave no active Global Administrator. In the output folder: `changes_m365_roles_….json` and `rollback_m365_roles_….csv`.

**What to do with it:**

- Tell the people concerned beforehand. Someone who loses a role may need a new way to do part of their job.
- `failed` lines: read the reason; usually a missing role or licence.
- **Undo:** `Set-T0M365RoleAssignment -Config $config -PlanPath output\2026-11-20\rollback_m365_roles_<time>.csv -Apply`
- Count again (6.2): target 1 should go down.

### 6.6 Require security keys for admins (target 2)

**What it does:** creates two Conditional Access rules: *admins must sign in with a security key or passkey*, and *block old sign-in methods* (which cannot do MFA). The emergency accounts are excluded. First in **report-only** mode: the rules only record what they would block.

**Rights you need:** `Connect-T0M365 -ReadWrite` as **Conditional Access Administrator** (or Security Administrator, or Global Administrator). Licence: Entra ID P1.

**Step 1: every admin gets a security key or passkey.** Each admin registers one at <https://mysignins.microsoft.com/security-info> (*Add sign-in method > Security key* or *Passkey*). Count again (6.2) until every privileged admin shows `phishing-resistant`.

**Step 2: create the rules in report-only mode.**

```powershell
New-T0M365AdminCaPolicy -Config $config            # test
New-T0M365AdminCaPolicy -Config $config -Apply     # create, report-only
```

**Step 3: wait a few working days**, then look in the Entra admin center under *Protection > Conditional Access > Insights and reporting* who would have been blocked. Fix those first.

**Step 4: switch the rules on.**

```powershell
Invoke-T0M365AdminInventory -Config $config        # fresh count first
New-T0M365AdminCaPolicy -Config $config -Apply -Enable
```

TargetZero refuses as long as an admin in the latest count has no security key or passkey, because that admin would be locked out.

**What you get:** `changes_m365_ca_….json` and `rollback_m365_ca_….csv` (each rule's previous state). The rules are visible in the Entra admin center as *T0 - Admins require phishing-resistant MFA* and *T0 - Block legacy authentication*.

**What to do with it:** count again (6.2). `mfa_enforced` should read `Y` for every admin, and target 2 should go down.

> **If Security Defaults is on**, TargetZero stops with a message: Microsoft does not allow Conditional Access rules while it is on. Switching it off removes MFA for **everyone** until the new rules work. Do this only with your IT provider: first a rule that keeps MFA for all users, then switch Security Defaults off and run step 2 right after.
>
> **Without Entra ID P1** these rules do not exist. `New-T0M365AdminCaPolicy -Config $config -Apply -UseSecurityDefaults` switches on Security Defaults instead: MFA for all admins and old sign-in methods blocked, but for all users. Discuss it with your IT provider first.

**Undo:** in the Entra admin center, set the rule to *Report-only* or *Off*. If you are locked out, sign in with an emergency account.

---

## 7. Google Workspace

All commands in this section run in a terminal, in your working folder.

### 7.1 One-time preparation: a sign-in key

**What it does:** gives TargetZero a way to sign in to your Google Workspace. About 15 minutes, once.

**Rights you need:** a **super admin** account, which may also create a Google Cloud project. Details: [permissions.md, Google Workspace](permissions.md#google-workspace-python).

1. Go to <https://console.cloud.google.com>, signed in as super admin, and create a **new project**, e.g. "TargetZero".
2. Search **Admin SDK API**, open it, click **Enable**.
3. *APIs & Services > OAuth consent screen*: choose **Internal**, name "TargetZero", fill in your e-mail, save.
4. *APIs & Services > Credentials > Create credentials > OAuth client ID*: type **Desktop app**, name "TargetZero", create.
5. Click **Download JSON**. Save it **outside** your working folder, e.g. `C:\Target0\secrets\targetzero-google.json`. Treat it like a password.
6. In `targetzero.yaml`:

   ```yaml
   gws:
     customer_id: my_customer
     admin_subject: ""
     credentials_file: C:\Target0\secrets\targetzero-google.json
   ```

Each time you run a Google command, a browser opens: sign in as super admin and allow the access shown.

### 7.2 Count admins and their MFA (targets 1 and 2)

**What it does:** lists every admin role holder in Google Workspace, whether they have 2-Step Verification, which second step they **actually used** in the last 30 days, and whether it is enforced. Reads only.

**Rights you need:** super admin (read permissions only are requested).

**Run it:**

```
py -m targetzero gws admins
```

Add `--days 90` to look at a longer sign-in history.

**What you get:** `1_gws_admins.csv`, `1_gws_role-plan.csv`, and the target 1 and 2 summaries. The columns mean the same as for Microsoft 365 (6.2), with two differences:

- `mfa_class` is based on what the admin **used** to sign in, not what is registered. `unknown` means 2-Step Verification is on but the admin did not sign in during the period: it counts until they do.
- `separate_admin_account = N` when the admin account sent e-mail recently.

**What to do with it:** the same as 6.2: decide who needs which role, mark it in the role plan (7.4), and give admins security keys (7.5). Roles given to a **group** are noted but not expanded: list those group members in `registers\manual_admins.csv` (8.4).

### 7.3 List your domains (target 5)

**What it does:** lists your Google Workspace domains for the discovery (9.1). Reads only.

**Run it:** `py -m targetzero gws domains`

**What you get:** `5_gws_domains.csv`. Run the discovery (9.1) on the same day.

### 7.4 Remove admin rights (target 1)

**What it does:** carries out the role plan: removes roles or moves admins into a separate organisational unit.

**Rights you need:** **super admin**. The browser asks you to allow two extra permissions (change users, change admin roles). If your IT provider set up a *service account* instead of 7.1, they must add those permissions temporarily; see [setup-gws.md](setup-gws.md#making-changes-03).

**Prepare the plan:** in `output\<date>\1_gws_role-plan.csv`, fill in `action` on the rows to change only:

| `action` | Effect | Extra column |
| --- | --- | --- |
| `revoke` | The role is taken away. | |
| `move-ou` | The admin moves to an organisational unit, e.g. one where only security keys are allowed. | `target_org_unit`, e.g. `/Admins` |

**Run it:**

```
py -m targetzero gws apply output\2026-11-20\1_gws_role-plan.csv            # test
py -m targetzero gws apply output\2026-11-20\1_gws_role-plan.csv --apply    # change
```

**What you get:** one line per row (`dry-run`, `refused`, `applied`, `failed`), a log and `rollback_gws_roles_….csv`. TargetZero never touches the emergency accounts and refuses to go below two super admins.

**What to do with it:** count again (7.2). To undo, apply the rollback file the same way.

### 7.5 Require security keys for admins (target 2, by hand)

Google does not allow this setting through its programming interface, so you do it in the Admin console:

1. Every admin registers a security key or passkey at <https://myaccount.google.com/signinoptions/twosv>.
2. Put the admins in their own organisational unit (7.4, `move-ou`).
3. Admin console: *Security > Authentication > 2-Step Verification*, select that unit, **Enforcement: On**, **Allowed methods: Only security key**.
4. Count again (7.2) after the admins have signed in once.

Create two emergency super admin accounts by hand, with security keys, and list them under `break_glass.gws` in `targetzero.yaml`.

---

## 8. Firewalls, servers and other systems

### 8.1 Firewalls: FortiGate, Palo Alto, Cisco ASA (targets 1, 2, 4)

**What it does:** reads a configuration **export file** and lists the firewall's admin accounts, their MFA, and whether the firewall's own admin page is reachable from the internet. It also notes the firmware version for the vulnerability check (9.6). TargetZero never connects to the firewall.

**Rights you need:** nothing on the firewall for TargetZero. The person who **makes the export** needs a full admin account on the firewall (FortiGate `super_admin`, Palo Alto `superuser`, Cisco ASA privilege 15). Details: [permissions.md, Firewalls](permissions.md#firewalls-and-other-devices-python).

**Get the export:**

| Device | How |
| --- | --- |
| Fortinet FortiGate | Web interface: your name (top right) > *Configuration > Backup*, **without** encryption. |
| Palo Alto | *Device > Setup > Operations > Export named configuration snapshot*, `running-config.xml`. |
| Cisco ASA | ASDM: *File > Show Running Configuration in New Window*, save as `.txt`. |

Put the files in a folder `exports` inside your working folder.

**Run it** (all devices of one brand in one command; a second run replaces the first):

```
py -m targetzero vendors fortigate exports\fw-office.conf exports\fw-branch.conf
py -m targetzero vendors panos exports\running-config.xml
py -m targetzero vendors asa exports\asa.txt
```

**What you get** (example for FortiGate):

| File | Content |
| --- | --- |
| `1_fortigate_admins.csv` | Every admin account, its profile, MFA and from where it may log in. |
| `4_fortigate_mgmt-exposure.csv` | Interfaces facing the internet where the admin page, SSH or SNMP is switched on. |
| `devices_fortigate.csv` | Model and firmware version, used by the vulnerability check. |

**What to do with it:**

- Admins with `mfa_class = none`: add MFA (e.g. FortiToken) or remove the account. `unknown` means the admin logs in through RADIUS, LDAP or SAML: check MFA on that server.
- A note "no trusted hosts set": that admin can log in from any address. Ask your firewall administrator to restrict it.
- Every row in `…_mgmt-exposure.csv`: switch off admin access on that internet-facing interface. Use a VPN to manage the firewall.
- **Delete the export files** when the campaign is done; they contain password hashes.

### 8.2 Server management cards: iDRAC, iLO (targets 1, 2)

**What it does:** logs in, read-only, to the management cards of your servers and lists their local accounts, roles, MFA settings and firmware version.

**Rights you need:** a **read-only account** on each card (iDRAC *Read Only*, iLO with only the *Login* privilege), and network access from your computer to the card. Creating that account needs an administrator of the card, usually your IT provider.

**Run it:** in a terminal (Windows PowerShell syntax shown):

```powershell
$env:TARGETZERO_REDFISH_USER = 'readonly'
$env:TARGETZERO_REDFISH_PASSWORD = Read-Host 'Password'
py -m targetzero vendors redfish --host idrac-01.acme.local --host ilo-02.acme.local --insecure
```

`--insecure` skips the certificate check, which most cards need because they use a self-signed certificate. Use it only on your own internal network.

**What you get:** `1_redfish_admins.csv`, the target 1 and 2 summaries and `devices_redfish.csv`.

**What to do with it:** remove unused accounts, and change default accounts (e.g. `root`, `Administrator`). Management cards must never be reachable from the internet; the port scan (9.3) checks that.

### 8.3 VMware vSphere (targets 1, 2)

**What it does:** logs in, read-only, to vCenter or ESXi, lists every permission (who has which role on what), and notes the version.

**Rights you need:** a user with the built-in **Read-only** role on the vCenter root, *Propagate to children* ticked. Installed with `"targetzero[gws,vsphere]"` (3.4).

**Run it:**

```powershell
$env:TARGETZERO_VSPHERE_USER = 'readonly@vsphere.local'
$env:TARGETZERO_VSPHERE_PASSWORD = Read-Host 'Password'
py -m targetzero vendors vsphere --host vcenter.acme.local
```

**What you get:** `1_vsphere_admins.csv`, the summaries and `devices_vsphere.csv`. All admins show MFA `unknown`, because vSphere does not tell whether the identity source enforces MFA. When you have confirmed that it does (e.g. sign-in through Entra ID with MFA), run again with `--mfa-via-idp`.

**What to do with it:** reduce the number of accounts with the *Administrator* role. Groups are listed as one row: check their members in your directory.

### 8.4 Everything else: the manual admin list (targets 1, 2)

**What it does:** counts the admins you list by hand, for systems TargetZero cannot read: on-premises Active Directory, other firewalls (e.g. SonicWall), VPN, backup software (e.g. Veeam), hypervisors, Exchange role groups, important cloud services.

**Active Directory:** if you have on-premises Windows servers with a domain, list every member of the groups **Domain Admins**, **Enterprise Admins**, **Schema Admins** and **Administrators**, and of **Account Operators**, **Server Operators**, **Backup Operators** and **Print Operators**. Include members of groups nested inside them. Use `system` = your domain name, e.g. `acme.local`. AD has no MFA of its own: use `mfa_class` = `phishing-resistant` only when a smart card is required for the account, otherwise `none`, or `unknown` when another product (e.g. Duo) is supposed to enforce MFA and you have not confirmed it.

**Rights you need:** none for TargetZero. To collect the information you need to see each system's admin list. For Active Directory any normal domain account can read group members, e.g. in *Active Directory Users and Computers*.

**Fill it in:** `registers\manual_admins.csv` in Excel, one row per admin account per system.

| Column | Fill in |
| --- | --- |
| `id` | Leave empty: TargetZero fills it in. |
| `system`, `account`, `role` | e.g. `Veeam backup`, `administrator`, `Veeam Administrator` |
| `privileged`, `permanent` | `Y` or `N` |
| `mfa_class` | `phishing-resistant`, `mfa`, `does-not-count`, `none` or `unknown` |
| `mfa_enforced`, `break_glass` | `Y` or `N` |
| `last_verified` | The date you checked, e.g. `2026-11-20` |

**Run it:**

```
py -m targetzero validate registers\manual_admins.csv
py -m targetzero registers manual-admins
```

**What you get:** `1_manual_admins.csv` and the target 1 and 2 summaries. **What to do with it:** the same as for the other platforms. Update the list after each change, and run the count again.

---

## 9. Your internet perimeter

These tools look at your organisation **from the internet**, the way an attacker does. They change nothing. Run them in this order the first time: 9.1 to 9.6.

**Rights you need:** no account anywhere, but **permission**: you may only check addresses and names that are yours. The port scan needs your explicit confirmation. Details: [permissions.md, Internet checks](permissions.md#internet-checks-python).

### 9.1 Find everything you have online (target 5)

**What it does:** collects your public names and addresses from your settings (`scope`), the domain lists of 6.3 and 7.3 (same day), and public certificate logs, which list every name a certificate was ever issued for. Everything new is added to `registers\inventory.csv`.

**Run it:**

```
py -m targetzero external discover
```

If your DNS provider lets you export a **zone file**, add it for a complete picture: `--zone-file exports\acme.com.zone:acme.com`.

**What you get:** `5_external_discovery.csv` (everything found, with addresses) and new rows in `registers\inventory.csv` with status `unreviewed`. Names that no longer resolve are listed but not added. A backup of the register is kept next to it.

**What to do with it:** go through the new rows in the inventory (9.2). You will usually find forgotten test sites, old campaigns and services you did not know about.

### 9.2 Complete the inventory (target 5)

**What it does:** `external enrich` visits each website in scope once and suggests the product, version and support status. `registers inventory` counts the rows that are still incomplete.

**Run it:**

```
py -m targetzero external enrich
py -m targetzero registers inventory
```

**What you get:** `5_external_enrich.csv` (suggestions; the register itself is not changed) and `5_inventory_rows.csv` (each incomplete row, with what is missing).

**What to do with it:** in `registers\inventory.csv`, fill in for each row:

| Column | Fill in |
| --- | --- |
| `owner` | The person responsible. |
| `purpose` | What it is for, e.g. "webshop". |
| `product`, `version` | e.g. `WordPress`, `6.6.2`. Copy from `5_external_enrich.csv` when it is right. The vulnerability check (9.6) needs the version. |
| `vendor_supported` | `Y` if the vendor still releases security updates. |
| `behind_waf` | `Y` / `N`, or `n/a` for things that are not websites (VPN, mail). |
| `status` | `reviewed`, or `retired` for things you have switched off. |
| `last_reviewed` | Today's date. |

Then validate and count again. Every thing you no longer need: switch it off, delete its DNS record, and set `status` to `retired`.

### 9.3 Open ports on your addresses (target 4)

**What it does:** checks about 50 ports on every address in `scope.ip_ranges`, the "doors" that should not face the internet: remote desktop, SSH, firewall and VPN admin pages, file sharing, databases. It compares the open ones with your list of approved ports.

**Rights you need:** **permission to scan every address** in `scope.ip_ranges` (you own or rent them, and your provider allows it). No rights on your computer. Tell your IT or internet provider beforehand: their alarm may go off, which is a good test of target 3.

**Run it:** take your laptop **out of the office network** (home internet or a phone hotspot), then:

```
py -m targetzero external scan --authorised
```

`--authorised` means "I confirm every address in my settings file is ours". Add `--internetdb` to also ask the free Shodan InternetDB service what it has seen on your addresses.

**What you get:** `4_external_exposure.csv`, one row per open port, with `approved` `Y` or `N`, and the target 4 count (open ports not approved).

**What to do with it:**

- **Management ports** (3389 remote desktop, 22 SSH, the firewall's admin page, 445 file sharing, databases): close them on the firewall. Use a VPN instead. This is the most important result of the whole campaign.
- Ports that must stay open (your website on 443, mail on 25): add them to `registers\approved_exposure.csv` with a reason, an owner, who approved it and a review date.
- Scan again after each firewall change.

### 9.4 Websites behind a WAF or CDN (target 4)

**What it does:** checks for each website whether it is behind a protective service (Cloudflare, Akamai, Azure Front Door, …) that filters attacks.

**Rights you need:** none for the basic check. With `--authorised` (origin test): the same permission as the port scan, for the addresses in `registers\origins.csv`.

**Run it:**

```
py -m targetzero external waf
```

If you know the real server address behind a protected site, list it in `registers\origins.csv` (`host,origin_ip`) and add `--authorised`: TargetZero then checks that this server refuses visitors who bypass the protection.

**What you get:** `4_external_waf.csv` with each site, the provider found (or none) and the result.

**What to do with it:** discuss unprotected websites with your web host. Names that are not websites (VPN portal, mail server): set `behind_waf` to `n/a` in the inventory. An origin that answers directly: ask your host to accept traffic from the protection service only.

### 9.5 Forgotten DNS records (target 5)

**What it does:** finds names that point to something that no longer exists: a deleted cloud site, an old storage bucket, an expired page at a service provider. Someone else could claim it and serve their content under your name.

**Run it:**

```
py -m targetzero external dangling-dns
```

**What you get:** `5_external_dangling-dns.csv`, each risky name with the service and the evidence.

**What to do with it:** ask whoever manages your DNS to **delete these records today**. This is quick and removes a real risk.

### 9.6 Known exploited vulnerabilities (target 6)

**What it does:** compares the products and versions in your inventory, and the firmware versions from the firewall and server exports (8.1 to 8.3, same day), with the official list of vulnerabilities that attackers are actively exploiting (CISA KEV). With a version, it checks whether that version is affected.

**Rights you need:** none. It downloads public lists. A free NVD API key makes it faster (set `NVD_API_KEY`).

**Run it** (after 8.1 to 8.3 and 9.2 on the same day):

```
py -m targetzero external kev
py -m targetzero registers findings
```

**What you get:** new rows in `registers\findings.csv`, each with a **deadline**, and `6_findings_overdue.csv` with the findings past their deadline (the target 6 count). Rows you already edited are never changed.

**What to do with it:**

1. For each finding: install the vendor's update, or apply their workaround, or switch the system off.
2. Set `status` to `patched` or `mitigated`, `closed_date` to today, and describe what you did in `action`.
3. Rows without a version say *confirm the version*: fill in the version in the inventory, and run `external kev` again.
4. Count again with `registers findings`.

---

## 10. Registers, exceptions and the scorecard

### 10.1 The scorecard (all targets)

**What it does:** collects today's counts of all tools into one table, subtracts what is covered by a signed exception, and compares with Day 1.

**Rights you need:** none.

**Run it:** after running the measurements you need, the same day:

```
py -m targetzero scorecard
```

**What you get:**

| File | Content |
| --- | --- |
| `output\<date>\scorecard.csv` | Per target: Day 1, today, excepted items, open exceptions, status, owner. |
| `output\history.csv` | One line per target per run: the trend. |
| `output\baseline.json` | The Day 1 numbers. Created at the first run; do not delete it. |

| Status | Meaning |
| --- | --- |
| **zero** | Done. |
| **open** | Items left to fix. |
| **incomplete** | A measurement missed something. Read its notes before you report the number. |
| **no data** | Not measured today. Never shown as zero. |

**What to do with it:** this is your report to management. Send the scorecard weekly during the campaign (with a short line per target: what was done, what is next), then monthly. Run the measurements again before each report; counts from another day are not used.

### 10.2 Exceptions: what cannot be fixed now

**What it does:** lets a manager accept a risk for a limited time, for example an old application that needs a port open until it is replaced. The item then no longer counts, but the exception is shown on the scorecard.

**Rights you need:** a **manager with the authority to accept the risk** signs it. That is an organisational right, not a technical one.

**Fill it in:** `registers\exceptions.csv`:

| Column | Example |
| --- | --- |
| `id` | `EXC-001` |
| `zero` | `4` |
| `items` | The item id from the summary file, e.g. `external:203.0.113.5/tcp-3389`. Several: separate with `;`. |
| `description` | What it is, and why it cannot be fixed now. |
| `compensating_control` | What limits the risk meanwhile, e.g. "only reachable from the accountant's IP address". |
| `accepted_by` | Name and function of the manager. |
| `signed_date` | `2026-11-20` |
| `expiry_date` | At most 90 days after signing. |

The item ids are in the `*.summary.json` files (open with Notepad), under `"items"`. Have the manager sign a printed copy and keep it.

An exception **without signer, without dates, or longer than 90 days is not accepted**: the scorecard shows it as a gap. Expired exceptions count again. Check the file with `py -m targetzero validate registers\exceptions.csv`.

### 10.3 Checking a file

`validate` checks a register or a summary file for mistakes (dates, allowed values, missing columns):

```
py -m targetzero validate registers\inventory.csv registers\findings.csv registers\exceptions.csv
```

Run it after every edit in Excel.

### 10.4 Targets 3 and 7: by hand

TargetZero does not count these two yet (planned for version 0.4); the scorecard shows **no data**. Keep them up to date by hand and report the numbers yourself.

- **Target 3, admins monitored:** make sure admin sign-ins, new admin roles and MFA changes reach someone who reads them every day (your IT provider, a security service, or at least a mailbox read by two people), and switch on the built-in alerts in Microsoft 365, Google Workspace and your firewall. Then, once a month, sign in with an admin account at an odd hour on each system and check that the warning arrived. Record each test in `registers\alert_tests.csv` (one row per test: system, account, time, whether the alert arrived, by whom) and check it with `validate`. The count is the number of admin accounts or systems where the test alert did not arrive.
- **Target 7, recovery pages:** for each internet-facing application in your inventory, copy `registers\recovery\_template.md` to a new file and fill it in with the owner, or ask the supplier to: how to shut it down (within 15 minutes), change its secrets (within 24 hours), rebuild it, and change its certificates. Test the shutdown once. The count is the number of internet-facing applications without a tested page.

---

# Part 3: Run the campaign

## 11. The 15 days: what to run when

| When | What | Sections |
| --- | --- | --- |
| Before day 1 | Install, working folder, settings, Google key, firewall exports, read-only device accounts. | 3, 4, 7.1, 8 |
| **Day 1: measure** | Microsoft 365 and Google counts and domains; firewall and device collectors; manual admin list; discovery, enrich, inventory count; port scan (from outside); WAF; forgotten DNS; vulnerabilities. Then the scorecard: these are your Day 1 numbers. | 6.1–6.3, 7.2–7.3, 8, 9, 10.1 |
| Day 1 | Read the results with the owners. Delete forgotten DNS records; close management ports. | 9.3, 9.5 |
| Days 2–3 | Emergency accounts. Security keys for all admins. | 6.4, 6.6 step 1, 7.5 |
| Days 3–6 | Role plans: remove unneeded admin rights. MFA rules in report-only mode. | 6.5, 7.4, 6.6 step 2 |
| Days 6–10 | Switch MFA rules on. Firewall fixes. Inventory completed. Vulnerabilities patched. | 6.6 step 4, 8.1, 9.2, 9.6 |
| Days 10–14 | Measure everything again. Exceptions for what cannot be fixed, signed. | 6–9, 10.2 |
| **Day 15: report** | Scorecard to management. | 10.1 |
| Then | Monthly: measure, scorecard, alert test, review exceptions before they expire. | 10 |

---

## 12. When something goes wrong

| Message | What to do |
| --- | --- |
| `'py' is not recognized` / `command not found: python3` | Python is not installed, or (python.org on Windows) "Add python.exe to PATH" was not ticked. Reinstall (3.2) and open a new terminal. |
| `Requires-Python >=3.11` / `No matching distribution found for targetzero` | Your Python is older than 3.11 (on a Mac often Apple's 3.9). See 3.2 and the pipx note in 3.4. |
| `externally-managed-environment` | Use pipx (3.4). |
| `No module named targetzero` | Run the install command of 3.4 again. |
| `No configuration found` | You are not in your working folder: `cd` to it first (5.1). |
| `... is invalid:` followed by a setting | A mistake in `targetzero.yaml`. Check spaces and quotes (4.2). |
| `running scripts is disabled on this system` | Windows: run the `Set-ExecutionPolicy` command of 3.3. |
| `The term 'Invoke-T0M365AdminInventory' is not recognized` | Run `Import-Module TargetZero` first, in PowerShell **7** (5.1). |
| `Need admin approval` in the browser | A Global Administrator must approve the permissions once (6.1). |
| `Insufficient privileges`, `Forbidden`, `Authorization_RequestDenied`, HTTP 403 | Your account lacks the role for this step. Check the *Rights you need* line of the section, and [permissions.md](permissions.md). With PIM: activate the role and sign in again. |
| `Request_ResourceNotFound` / `Role holder … is not a user that exists` | A deleted user still holds a role. Remove that assignment (6.2, point 5). |
| `Security Defaults is on` | See the warning in 6.6. Do not switch it off on your own. |
| `Google Workspace support is not installed` | Install with `[gws]` (3.4). |
| A count shows `(incomplete)` | Read the `note:` lines. Usually a missing licence, permission, or a site that did not answer. |
| `crt.sh failed … 502` | A public service was busy. Try again later. |
| `validate` reports problems | Usually a date not written as `2026-11-20`, or a value like `yes` instead of `Y` (5.5). |
| A change did something you did not want | Apply the rollback file (5.4). For Microsoft 365 MFA rules: set the rule to *Report-only* or *Off* in the Entra admin center. Locked out: sign in with an emergency account. |

Still stuck? Ask your IT provider, or open an issue at <https://github.com/wiresecurity/TargetZero/issues>. Never include names, e-mail addresses, IP addresses, domain names or keys: replace them with `example.com` or `203.0.113.x`. Security problems in TargetZero itself: see [SECURITY.md](../SECURITY.md).

---

## 13. Words used in this guide

| Word | Meaning |
| --- | --- |
| **Admin / administrator** | An account that can change settings or other people's accounts. |
| **Break-glass account** | An emergency admin account, used only when normal admins cannot sign in. |
| **Conditional Access** | Microsoft 365 rules that decide who may sign in, and how. Needs Entra ID P1. |
| **CSV file** | A simple table file. Excel opens it. |
| **DNS record** | An entry that links a name like `shop.acme.com` to an address or service. |
| **Dry run** | A test run: TargetZero shows what it would do, and changes nothing. |
| **Entra ID** | The Microsoft 365 user and admin directory (formerly Azure AD). |
| **Global Reader** | A Microsoft 365 role that can see everything an administrator sees, and change nothing. |
| **KEV** | The list of vulnerabilities that attackers are known to exploit, kept by the US agency CISA. |
| **MFA** | Multi-factor authentication: a second proof besides the password. |
| **Origin** | The real server behind a WAF/CDN. It should only accept traffic from the WAF/CDN. |
| **Phishing-resistant MFA** | MFA that a fake website cannot steal: a security key (e.g. YubiKey) or a passkey. SMS codes are not phishing-resistant. |
| **PIM** | Privileged Identity Management (Entra ID P2): admins switch their role on only when needed. |
| **Port** | A numbered "door" on an internet address. Some should never face the internet (e.g. 3389, remote desktop). |
| **Register** | A list you keep up to date by hand, in the `registers` folder. |
| **Rollback file** | A file written by every change, which undoes it when applied. |
| **Scope** | The domains and addresses you own and allow TargetZero to check. |
| **Security Defaults** | Microsoft's free basic protection, for organisations without Conditional Access. |
| **Super admin** | The Google Workspace role with all rights. |
| **Terminal** | The window where you type commands. |
| **WAF / CDN** | A protective service in front of a website (e.g. Cloudflare) that filters attacks. |
