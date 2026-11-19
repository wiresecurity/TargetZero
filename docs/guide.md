# TargetZero step by step

This guide is for people who look after IT in a small organisation without being IT specialists. You need no programming knowledge. You do need to be careful, because TargetZero looks at, and can change, the most sensitive parts of your organisation: your administrator accounts and what you expose to the internet.

Read the whole guide once before you start. It takes about 20 minutes.

**Contents**

1. [What TargetZero does](#1-what-targetzero-does)
2. [Before you start: what you need](#2-before-you-start-what-you-need)
3. [Ten rules to stay safe](#3-ten-rules-to-stay-safe)
4. [Install the software (once)](#4-install-the-software-once)
5. [Create your working folder (once)](#5-create-your-working-folder-once)
6. [Fill in the settings file](#6-fill-in-the-settings-file)
7. [Day 1: measure](#7-day-1-measure)
8. [Read the results](#8-read-the-results)
9. [Days 2 to 10: fix](#9-days-2-to-10-fix)
10. [Exceptions: what cannot be fixed now](#10-exceptions-what-cannot-be-fixed-now)
11. [The scorecard: report to management](#11-the-scorecard-report-to-management)
12. [When something goes wrong](#12-when-something-goes-wrong)
13. [Words used in this guide](#13-words-used-in-this-guide)

---

## 1. What TargetZero does

The Target 0 campaign (see [TargetZero.pdf](../TargetZero.pdf)) asks you to bring seven numbers to zero within 15 days. TargetZero helps in three ways:

| It… | Example |
| --- | --- |
| **counts** | "You have 6 administrators with permanent full rights, 2 of them without proper MFA." |
| **helps you fix** | Removes admin rights you marked for removal, creates emergency accounts, switches on MFA rules. |
| **reports** | Builds the scorecard you give to management every week. |

What it covers:

| Target | Microsoft 365 | Google Workspace | Firewalls, servers, internet |
| --- | --- | --- | --- |
| 1 Admins with permanent full rights | ✔ count and fix | ✔ count and fix | ✔ count (FortiGate, Palo Alto, Cisco ASA, iDRAC/iLO, vSphere; others by hand) |
| 2 Admins without MFA | ✔ count and fix | ✔ count | ✔ count |
| 3 Admins not monitored | you keep a simple list by hand | | |
| 4 Internet exposure | | | ✔ count |
| 5 Inventory of what is online | ✔ your domains | ✔ your domains | ✔ finds and lists your sites |
| 6 Known vulnerabilities | | | ✔ count |
| 7 Recovery plans | you fill in a template | | |

What it does **not** do: it does not watch your systems day and night, it does not send alerts, and it does not install anything on your servers. It runs on your own computer when you start it, and stops when it is done.

---

## 2. Before you start: what you need

### People

- **One owner** for the campaign (probably you).
- **One manager** who can sign exceptions (see section 10).
- **Your IT provider**, if you have one. Tell them you are doing this. If they manage your Microsoft 365, Google Workspace or firewall, it is best to do the *fixing* part (section 9) together with them.

### A computer

- A Windows 10/11 PC or a Mac that you control, with internet access.
- About 1 GB of free disk space.
- Preferably **not** a shared computer. The results contain names of administrators and details of your network.
- The disk should be encrypted (BitLocker on Windows, FileVault on Mac). Ask your IT provider if you are not sure.

### Accounts and permissions

| For | You need | Why |
| --- | --- | --- |
| Microsoft 365, counting | An account with the **Global Reader** role | Reads all admin roles and MFA settings, changes nothing. |
| Microsoft 365, first time only | Someone with **Global Administrator** | To approve ("consent to") the read permissions once. |
| Microsoft 365, fixing | **Privileged Role Administrator** and **Conditional Access Administrator**, or Global Administrator | To change admin roles and MFA rules. |
| Google Workspace | A **super admin** account, and access to Google Cloud Console | To create the sign-in key TargetZero uses (section 7.3). |
| Firewalls | Someone who can **export the configuration** | TargetZero reads the export file, it never logs in to the firewall. |

### Time

- Installation and settings: 1 to 2 hours, once.
- Day 1 measurement: 1 to 3 hours.
- Then a few hours per week during the campaign.

---

## 3. Ten rules to stay safe

These are the most important part of this guide.

1. **Every change command first shows what it *would* do, and changes nothing.** Only when you add `-Apply` (PowerShell) or `--apply` (Python) does it change something. Always run without it first, read the result, and only then run again with it.
2. **Make changes only when you can deal with surprises.** Not on a Friday evening. Preferably with a second person, or your IT provider, available.
3. **Create the emergency (break-glass) accounts before you remove any admin rights.** They are your way back in if you lock yourself out (section 9.1).
4. **Never switch on the MFA rule for admins before every admin has a security key or passkey.** TargetZero refuses to do it when it sees an admin without one, but check yourself too.
5. **Keep the results private.** The `output` and `registers` folders contain admin names, network details and weaknesses. Do not e-mail them around, do not put them on a public share, do not upload them anywhere.
6. **Never scan addresses that are not yours.** The internet scan only checks what you list in the settings file. List only addresses your organisation owns or rents, with permission of whoever manages them. Scanning other people's systems can be illegal.
7. **Run the internet scan from outside your office network.** From a home connection or a phone hotspot. From inside the office you see your own network, not what attackers see.
8. **Firewall export files contain secrets** (password hashes, keys). Store them only in your working folder, and delete them when the campaign is done.
9. **Keep the rollback files.** Every change command writes a file named `rollback_…csv`. With it, you can undo that change. Do not delete these files during the campaign.
10. **When in doubt, stop and ask.** Nothing in this campaign is so urgent that a wrong change is better than a day's delay. Your IT provider, or Wire Security, can help.

---

## 4. Install the software (once)

You install Python and TargetZero. For Microsoft 365 you also install PowerShell 7 and the TargetZero module for it.

### 4.1 Open a terminal

A terminal is a window where you type commands. You will copy commands from this guide, paste them, and press **Enter**.

- **Windows:** press the Windows key, type `Terminal`, and open **Terminal** (or **Windows PowerShell**).
- **Mac:** press **Cmd + Space**, type `Terminal`, press **Enter**.

Tips:

- In the commands below, folders like `C:\Tools\TargetZero` are examples. Replace them with your own.
- Windows writes folders with `\`, a Mac with `/`. The examples use Windows style; on a Mac write `exports/fw-office.conf` instead of `exports\fw-office.conf`.

### 4.2 Install Python

1. Go to <https://www.python.org/downloads/> and download the latest Python 3 (3.11 or newer).
2. Run the installer.
   - **Windows: tick "Add python.exe to PATH"** at the bottom of the first screen, then click *Install Now*.
   - **Mac:** click through the installer. Afterwards, open the *Python 3.x* folder in Applications and double-click *Install Certificates.command*.
3. Close your terminal and open a new one. Check:
   - Windows: `py --version`
   - Mac: `python3 --version`

   You should see `Python 3.12.x` or similar.

In the rest of this guide, `py` is used for Windows. **On a Mac, type `python3` wherever the guide says `py`.**

### 4.3 Install PowerShell 7 (Microsoft 365 only)

Windows already has an older *Windows PowerShell 5*. TargetZero needs the newer **PowerShell 7**.

- **Windows:** open the Microsoft Store, search for **PowerShell**, install it. Or in a terminal: `winget install --id Microsoft.PowerShell`
- **Mac:** download the `.pkg` file for macOS from <https://aka.ms/powershell-release?tag=lts> and install it.

From now on, when the guide says "open PowerShell 7", start the app called **PowerShell** (Windows: *PowerShell 7* in the Start menu; Mac: type `pwsh` in Terminal). Check with:

```powershell
$PSVersionTable.PSVersion
```

It must say 7.4 or higher.

Then install two helper modules. In PowerShell 7:

```powershell
Install-Module Microsoft.Graph.Authentication, powershell-yaml -Scope CurrentUser
```

Answer **Y** (yes) if it asks whether you trust the repository *PSGallery*.

**Windows only:** allow scripts you downloaded to run, for your user only:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 4.4 Install TargetZero

TargetZero is published on PyPI, the standard place for Python software: <https://pypi.org/project/targetzero/>. In a terminal (not necessarily PowerShell 7):

- Windows:

  ```
  py -m pip install "targetzero[gws]"
  ```

- Mac:

  ```
  python3 -m pip install "targetzero[gws]"
  ```

`[gws]` adds Google Workspace support. Leave it out if you do not use Google Workspace (`py -m pip install targetzero`). If you have VMware vSphere, use `"targetzero[gws,vsphere]"`.

Check it works:

```
py -m targetzero --version
```

You should see `targetzero 0.3.2` or newer.

**Updating later.** New versions fix problems and add checks. To update, run the same install command with `--upgrade`:

```
py -m pip install --upgrade "targetzero[gws]"
```

### 4.5 Download the Microsoft 365 module (Microsoft 365 only)

The Microsoft 365 part is a PowerShell module. Until it is published on the PowerShell Gallery, you download it from GitHub:

1. Go to the latest release: <https://github.com/wiresecurity/TargetZero/releases/latest>.
2. Under **Assets**, click **Source code (zip)**.
3. Unzip it to a permanent place, for example:
   - Windows: `C:\Tools\TargetZero`
   - Mac: a folder `Tools/TargetZero` in your home folder

   Make sure that folder contains `README.md`, `powershell` and the other folders directly, not inside an extra sub-folder. If the zip created a sub-folder such as `TargetZero-0.3.2`, move its contents up one level.
4. **Windows only:** mark the downloaded files as trusted. In PowerShell 7:

   ```powershell
   Get-ChildItem C:\Tools\TargetZero -Recurse | Unblock-File
   ```

To update the module later, download the new release and replace the folder's contents. Use the same version as your Python package (`py -m targetzero --version`).

> In this guide all Python commands start with `py -m targetzero` (Mac: `python3 -m targetzero`). That always works, even when the shorter `targetzero` command is not found.

---

## 5. Create your working folder (once)

Your results go into a **working folder**, separate from the TargetZero download. Never put your results inside the TargetZero folder.

1. Create the folder, for example `C:\Target0\Acme` (Mac: `Target0/Acme` in your home folder). Use one folder per organisation.
2. In a terminal, go to it and let TargetZero set it up:

   Windows:

   ```
   cd C:\Target0\Acme
   py -m targetzero init
   ```

   Mac:

   ```
   cd ~/Target0/Acme
   python3 -m targetzero init
   ```

It creates:

| File or folder | What it is |
| --- | --- |
| `targetzero.yaml` | Your settings (next section). |
| `privileged_roles.yaml` | Which admin roles count as "full admin". The default list is fine to start. |
| `registers\` | Lists you keep up to date by hand, in Excel. |
| `output\` | Created later. One sub-folder per day with all results. |

**Every time you use TargetZero, first go to this working folder** with `cd`. TargetZero looks for `targetzero.yaml` in the folder you are in.

---

## 6. Fill in the settings file

Open `targetzero.yaml` with a plain text editor: **Notepad** on Windows, **TextEdit** on Mac (in TextEdit: *Format > Make Plain Text*). Do not use Word.

Change these parts:

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
| `owners` | Who is responsible for each of the seven targets. |
| `break_glass` | The names of your two emergency admin accounts per platform. If you do not have them yet, keep the example names but use your own domain. For Microsoft 365 they must end in `.onmicrosoft.com` (find yours in the Microsoft 365 admin center under *Settings > Domains*). Remove the platform you do not use. |
| `scope` → `domains` | Your own internet domain names, e.g. `acme.com`. |
| `scope` → `ip_ranges` | Your public internet addresses. Ask your internet or IT provider: "Which fixed public IP addresses do we have?" A single address is written like `203.0.113.17/32`. **Only addresses you own or rent.** |

Rules for this file:

- Keep the spaces at the start of lines exactly as in the example. Use spaces, not tabs.
- Keep the quotes around `"1"` to `"7"`.
- Keep everything after `#` on a line as it is, or delete it; it is a comment.

Check your settings:

```
py -m targetzero scorecard
```

If there is a mistake, it tells you which line. If all is well, you see a table with seven rows reading **no data**. That is correct: nothing has been measured yet.

---

## 7. Day 1: measure

Do only the parts that apply to you. Each step only **reads** information; nothing is changed.

### 7.1 Microsoft 365

1. Open **PowerShell 7** and go to your working folder:

   ```powershell
   cd C:\Target0\Acme
   Import-Module C:\Tools\TargetZero\powershell\TargetZero
   $config = Import-T0Config
   ```

2. Sign in:

   ```powershell
   Connect-T0M365 -Config $config
   ```

   A browser window opens. Sign in with your **Global Reader** account.
   **The first time**, Microsoft asks to approve permissions for *Microsoft Graph Command Line Tools*. All of them are read-only. If you are not a Global Administrator, a Global Administrator must sign in once and approve them for the organisation.

3. Count the admins and their MFA:

   ```powershell
   Invoke-T0M365AdminInventory -Config $config
   ```

4. List your domains (used in step 7.5):

   ```powershell
   Get-T0M365Domain -Config $config
   ```

Typing `Import-Module`, `$config = …` and `Connect-T0M365` is needed each time you open a new PowerShell window.

### 7.2 Google Workspace: one-time preparation

TargetZero needs a sign-in key from Google. This takes about 15 minutes, once. Do it signed in as a super admin.

1. Go to <https://console.cloud.google.com> and create a **new project**, e.g. "TargetZero".
2. In the search bar, search **Admin SDK API**, open it, and click **Enable**.
3. Go to **APIs & Services > OAuth consent screen**. Choose **Internal**, give it a name ("TargetZero"), fill in your e-mail, and save.
4. Go to **APIs & Services > Credentials > Create credentials > OAuth client ID**. Choose **Desktop app**, name it "TargetZero", and create it.
5. Click **Download JSON**. Save the file **outside** your working folder, e.g. `C:\Target0\secrets\targetzero-google.json`. This file is a key: treat it like a password.
6. In `targetzero.yaml`, under `gws:`, fill in:

   ```yaml
   gws:
     customer_id: my_customer
     admin_subject: ""
     credentials_file: C:\Target0\secrets\targetzero-google.json
   ```

### 7.3 Google Workspace: measure

In a terminal, in your working folder:

```
py -m targetzero gws admins
py -m targetzero gws domains
```

The first time, a browser opens. Sign in with your **super admin** account and allow access. TargetZero asks only for read permissions.

### 7.4 Firewalls and other devices

TargetZero reads an **export file** of the configuration. It never connects to the firewall itself.

| Device | How to get the export |
| --- | --- |
| Fortinet FortiGate | Web interface: your name (top right) > *Configuration > Backup*, **without** encryption. |
| Palo Alto | *Device > Setup > Operations > Export named configuration snapshot*, choose `running-config.xml`. |
| Cisco ASA | In ASDM: *File > Show Running Configuration in New Window*, save as a `.txt` file. |

Put the files in a sub-folder `exports` of your working folder, then (all files of one brand in one command):

```
py -m targetzero vendors fortigate exports\fw-office.conf exports\fw-branch.conf
py -m targetzero vendors panos exports\running-config.xml
py -m targetzero vendors asa exports\asa.txt
```

For server management cards (iDRAC, iLO) and VMware vSphere, see [vendors.md](vendors.md); these need a read-only login and are best done by your IT provider.

**Everything else** (other firewalls, VPN, backup software, hypervisors, cloud services with admin roles): fill in `registers\manual_admins.csv` in Excel, one row per admin account. Use `Y`/`N` for yes/no columns. Allowed values for `mfa_class`: `phishing-resistant` (security key or passkey), `mfa` (authenticator app or code), `does-not-count` (SMS or e-mail code), `none`, `unknown`. Then:

```
py -m targetzero registers manual-admins
```

### 7.5 What you have on the internet

These steps contact your own websites and public information sources. They do not change anything.

1. **Find your sites and addresses.** This adds everything found to `registers\inventory.csv`:

   ```
   py -m targetzero external discover
   ```

2. **Open ports scan.** Take your laptop **out of the office network**: connect to a phone hotspot or your home internet. Then:

   ```
   py -m targetzero external scan --authorised
   ```

   `--authorised` means: "I confirm that every address in my settings file is ours." It is required on purpose.

3. **Known vulnerabilities.** Back on any network:

   ```
   py -m targetzero external kev
   ```

4. **Websites behind protection, and forgotten DNS records:**

   ```
   py -m targetzero external waf
   py -m targetzero external dangling-dns
   ```

### 7.6 The Day 1 scorecard

```
py -m targetzero scorecard
```

The first numbers are stored as your **Day 1** baseline. Do not worry if they are high: that is what the campaign is for.

---

## 8. Read the results

Every command prints a short summary, for example:

```
Zero 1 m365/admins: 4
Zero 2 m365/mfa: 2
  note: Entra ID licence: P1
```

The details are in `output\<today's date>\`. Open the `.csv` files with Excel.

| File | What you see |
| --- | --- |
| `1_m365_admins.csv`, `1_gws_admins.csv`, `1_fortigate_admins.csv`, … | Every admin, their role, whether it is permanent, their MFA. |
| `4_external_exposure.csv` | Open ports on your internet addresses, and whether they are on your approved list. |
| `4_external_waf.csv` | Which websites are behind a WAF/CDN. |
| `5_inventory_rows.csv` | Which inventory rows are incomplete, and why. |
| `6_findings_overdue.csv` | Known vulnerabilities and their deadline. |
| `scorecard.csv` | The seven numbers. |

How to read the important columns:

- `permanent = Y` and `privileged = Y`: this account always has full admin rights. Target 1 wants these gone, except the two emergency accounts.
- `mfa_class`: `phishing-resistant` is the goal. `mfa` is acceptable for now. `does-not-count` (SMS), `none` and `unknown` count against target 2.
- `mfa_enforced = N`: even if the person has MFA, nothing forces it; a stolen password may be enough.
- `notes`: explanations in plain words. Always read them.
- In a summary, **incomplete** means TargetZero could not see everything (missing permission, licence, or a site that did not answer). Do not trust that number until the note is resolved.

**Excel warning.** If you edit a CSV file in Excel:

- With Belgian, Dutch, French or German regional settings, Excel may show the whole row in one column. Open the file through **Data > From Text/CSV** and choose *Comma* as the delimiter instead of double-clicking it.
- Save with **File > Save As > CSV UTF-8**. Excel may then use semicolons instead of commas; TargetZero reads both.
- Excel may change dates like `2026-11-19` into `19/11/2026`. TargetZero needs `2026-11-19`. Before typing dates, select the column and set the format to **Text**.
- After editing a register, check it:

  ```
  py -m targetzero validate registers\inventory.csv
  ```

---

## 9. Days 2 to 10: fix

Do the steps below **in this order**. Each change command first runs as a **test** (it shows `dry-run` and what it would do). Only add `-Apply` / `--apply` after you have read that output and agree.

### 9.1 Emergency accounts first (Microsoft 365)

Emergency ("break-glass") accounts are two admin accounts used only when everything else fails, for example when an MFA rule locks everybody out.

In PowerShell 7 (after the three lines from 7.1), sign in with an account that can make changes:

```powershell
Connect-T0M365 -Config $config -ReadWrite
New-T0M365BreakGlassAccount -Config $config
```

Read the result. If it looks right:

```powershell
New-T0M365BreakGlassAccount -Config $config -Apply
```

It asks for confirmation for each step. Then:

1. **The passwords are shown once on screen, and nowhere else.** Write them down or print them immediately. Store them in a safe. Make sure two people know where.
2. Sign in once with each emergency account, and register **two security keys** (FIDO2, e.g. a YubiKey) per account. Store them with the passwords.
3. Make sure `break_glass` in `targetzero.yaml` lists exactly these two accounts.
4. Ask your IT provider to make sure someone is warned whenever these accounts are used (target 3).

For Google Workspace, create two super admin accounts by hand in the Admin console, with security keys, and put their names under `gws:` in `break_glass`.

### 9.2 Security keys for all admins

Before tightening MFA, give every remaining administrator a **security key or passkey**, and let them register it:

- Microsoft 365: <https://mysignins.microsoft.com/security-info>, *Add sign-in method > Security key* or *Passkey*.
- Google: <https://myaccount.google.com/signinoptions/twosv>, *Security keys* or *Passkeys*.

Then measure again (7.1 or 7.3) and check that their `mfa_class` reads `phishing-resistant`.

### 9.3 Remove admin rights nobody needs

The admin count (7.1, 7.3) also wrote a **plan file**: `1_m365_role-plan.csv` and/or `1_gws_role-plan.csv` in today's output folder. One row per admin role.

1. Open the plan in Excel. **Leave every row empty** except the ones you want to change.
2. In the `action` column, write:

   | Platform | action | Effect |
   | --- | --- | --- |
   | Microsoft 365 | `remove` | The role is taken away. |
   | Microsoft 365 (with Entra ID P2) | `make-eligible` | The person can switch the role on when needed, for a short time. |
   | Microsoft 365 (with Entra ID P2) | `time-bound` | The role ends on the date in `new_end_date`. |
   | Google Workspace | `revoke` | The role is taken away. |
   | Google Workspace | `move-ou` | The admin moves to the org unit in `target_org_unit`, e.g. `/Admins`. |

3. Save as CSV UTF-8.
4. Test (nothing changes):

   - Microsoft 365, in PowerShell 7:
     ```powershell
     Set-T0M365RoleAssignment -Config $config -PlanPath output\2026-11-19\1_m365_role-plan.csv
     ```
   - Google Workspace:
     ```
     py -m targetzero gws apply output\2026-11-19\1_gws_role-plan.csv
     ```

   Every row shows `dry-run` (would do it) or `refused` (will not do it, with the reason). TargetZero refuses, among others, to touch emergency accounts and to remove the last Global Administrator (Microsoft) or go below two super admins (Google).
5. If you agree, run the same command again with `-Apply` (Microsoft) or `--apply` (Google). It asks for confirmation.
6. **Undo, if needed:** the output folder now has `rollback_m365_roles_….csv` or `rollback_gws_roles_….csv`. Run the same command with that file as the plan, with `-Apply`/`--apply`, and the change is reversed.

For Google Workspace changes, the browser asks you once to allow two extra permissions (to change users and admin roles). If your IT provider set TargetZero up with a *service account* instead of the sign-in key from section 7.2, they must add those permissions first; see [setup-gws.md](setup-gws.md#making-changes-03).

### 9.4 Switch on MFA rules for admins (Microsoft 365)

This creates two Conditional Access rules: *admins must use a security key or passkey*, and *block old sign-in methods*. The emergency accounts are excluded.

> **Careful if Security Defaults is on.** Many small Microsoft 365 tenants have *Security Defaults* switched on (Entra admin center > *Identity > Overview > Properties > Manage security defaults*). Microsoft does not allow Conditional Access rules while it is on, so TargetZero stops with a message saying so. Switching Security Defaults off removes MFA for **everyone** until the new rules are active. Do this only together with your IT provider, who should first create a rule that keeps MFA for all users, and then switch Security Defaults off and run the commands below **right after each other**.

1. Create them in **report-only** mode (they only watch, they do not block yet):

   ```powershell
   New-T0M365AdminCaPolicy -Config $config
   New-T0M365AdminCaPolicy -Config $config -Apply
   ```

2. Wait **a few working days**. Then look in the Entra admin center under *Protection > Conditional Access > Insights and reporting* for who would have been blocked. Fix those first (usually: a missing security key).
3. Measure again (`Invoke-T0M365AdminInventory`), then switch the rules on:

   ```powershell
   New-T0M365AdminCaPolicy -Config $config -Apply -Enable
   ```

   TargetZero refuses this as long as an admin in the latest measurement has no security key or passkey.

Without the Entra ID P1 licence these rules do not exist; TargetZero then offers **Security Defaults** instead (`-UseSecurityDefaults`). Discuss this with your IT provider first: Security Defaults applies to all users, not only admins.

For Google Workspace, set *Security > 2-Step Verification > Allowed methods: Only security key* on the org unit of your admins in the Admin console.

### 9.5 Internet exposure

TargetZero does not change firewalls. Use the results to ask your IT provider or firewall administrator for specific changes:

- `4_external_exposure.csv`: every open port that is not on your approved list. Management ports (RDP, SSH, the firewall's own admin page) must be closed to the internet. Ports that must stay open go into `registers\approved_exposure.csv`, with a reason and who approved it.
- `4_fortigate_mgmt-exposure.csv` (or `panos`, `asa`): firewall admin pages reachable from the internet. Switch them off on the internet-facing interface.
- `4_external_waf.csv`: websites not behind a WAF/CDN. Discuss with your web host. If a name is not a website (a VPN portal, mail), put `n/a` in the `behind_waf` column of that row in `registers\inventory.csv`.
- `5_external_dangling-dns.csv`: DNS records that point to something that no longer exists. Ask whoever manages your DNS to delete them.
- `6_findings_overdue.csv` and `registers\findings.csv`: update, mitigate or switch off the affected system. Then set the `status` of that row to `patched` or `mitigated`.

After each round of changes, measure again (section 7) and run the scorecard.

### 9.6 Fill in the inventory

Open `registers\inventory.csv`. For every row fill in: `owner`, `purpose`, `product`, `version`, `vendor_supported` (Y/N), set `status` to `reviewed`, and `last_reviewed` to today's date (`2026-11-19`). `py -m targetzero external enrich` writes suggestions in `5_external_enrich.csv` to help you. Rows for things you no longer use: set `status` to `retired`.

Check and count:

```
py -m targetzero validate registers\inventory.csv
py -m targetzero registers inventory
```

---

## 10. Exceptions: what cannot be fixed now

Sometimes something cannot reach zero in time, for example an old application that needs a port open until it is replaced. Then you record an **exception** in `registers\exceptions.csv`:

| Column | Example |
| --- | --- |
| `id` | `EXC-001` |
| `zero` | `4` (which target) |
| `items` | The `id` of the item from the summary file, e.g. `external:203.0.113.5/tcp-3389`. Several: separate with `;`. |
| `description` | What it is, and why it cannot be fixed now. |
| `compensating_control` | What limits the risk meanwhile, e.g. "only reachable from the accountant's IP address". |
| `accepted_by` | Name and function of the manager who accepts the risk. |
| `signed_date` | `2026-11-20` |
| `expiry_date` | At most 90 days after signing, e.g. `2027-02-15`. |

Have the manager actually sign a printed copy, and keep it.

An exception **without signer, without dates, or longer than 90 days is not accepted**: the scorecard shows it as a gap. Expired exceptions count again.

Tip: you find the `id` values in the `*.summary.json` files in the output folder (open them with Notepad), under `"items"`.

---

## 11. The scorecard: report to management

```
py -m targetzero scorecard
```

You get `output\<date>\scorecard.csv` (open in Excel) with, per target: the Day 1 number, today's number, open exceptions, status and owner. `output\history.csv` holds the trend over time.

| Status | Meaning |
| --- | --- |
| **zero** | Done. |
| **open** | Still items to fix. |
| **incomplete** | The measurement missed something; read the notes before reporting the number. |
| **no data** | Not measured yet. This is never shown as zero. |

Report weekly until all seven are zero, then monthly. Run the measurements of section 7 again before each report.

Targets 3 and 7 are partly manual: keep `registers\alert_tests.csv` (the monthly test that an admin login at an odd hour is noticed) and the recovery pages in `registers\recovery\` up to date.

---

## 12. When something goes wrong

| Message | What to do |
| --- | --- |
| `'py' is not recognized` / `command not found: python3` | Python is not installed, or on Windows "Add python.exe to PATH" was not ticked. Reinstall Python (4.2) and open a new terminal. |
| `No configuration found` | You are not in your working folder. `cd` to it first (section 5). |
| `... is invalid:` followed by a line | A mistake in `targetzero.yaml`. The message names the setting. Check spaces and quotes (section 6). |
| `Security Defaults is on` | See the warning in 9.4. Do not switch Security Defaults off on your own. |
| `running scripts is disabled on this system` | Windows only: run the two Windows-only commands in 4.3 and 4.5. |
| `The term 'Invoke-T0M365AdminInventory' is not recognized` | Run `Import-Module C:\Tools\TargetZero\powershell\TargetZero` first (in PowerShell **7**). |
| `Need admin approval` in the browser | A Global Administrator must sign in once and approve the permissions (7.1). |
| `Insufficient privileges` / `Forbidden` / HTTP 403 | Your account lacks the role from section 2. |
| `Google Workspace support is not installed` | Install again with `[gws]` (4.4). |
| `No module named targetzero` | TargetZero is not installed for this Python. Run the install command in 4.4 again. |
| A count shows `(incomplete)` | Read the `note:` lines under it. Often a site did not answer, or a licence or permission is missing. |
| `crt.sh failed … 502` | A public website TargetZero uses was busy. Try again later. |
| `validate` reports problems in a register | Usually a date in the wrong format (must be `2026-11-19`) or a value that is not allowed (e.g. `yes` instead of `Y`). |
| A change did something you did not want | Use the rollback file (9.3, step 6). For Conditional Access: in the Entra admin center, set the rule to *Report-only* or *Off*. If you are locked out: sign in with an emergency account. |

Still stuck? Ask your IT provider, or open an issue at <https://github.com/wiresecurity/TargetZero/issues>. Never include names, e-mail addresses, IP addresses, domain names or keys: replace them with `example.com` or `203.0.113.x`. Security problems in TargetZero itself: see [SECURITY.md](../SECURITY.md).

---

## 13. Words used in this guide

| Word | Meaning |
| --- | --- |
| **Admin / administrator** | An account that can change settings or other people's accounts. |
| **Break-glass account** | An emergency admin account, used only when normal admins cannot sign in. |
| **CSV file** | A simple table file. Excel opens it. |
| **Dry run** | A test run: TargetZero shows what it would do, and changes nothing. |
| **MFA** | Multi-factor authentication: a second proof besides the password. |
| **Phishing-resistant MFA** | MFA that a fake website cannot steal: a security key (e.g. YubiKey) or a passkey. SMS codes are not phishing-resistant. |
| **Conditional Access** | Microsoft 365 rules that decide who may sign in, and how. Needs the Entra ID P1 licence. |
| **Security Defaults** | Microsoft's free basic protection, for organisations without Conditional Access. |
| **PIM** | Privileged Identity Management (Entra ID P2): admins switch their role on only when needed. |
| **Port** | A numbered "door" on an internet address. Some doors should never face the internet (e.g. RDP, 3389). |
| **WAF / CDN** | A protective service in front of a website (e.g. Cloudflare) that filters attacks. |
| **Origin** | The real server behind a WAF/CDN. It should only accept traffic from the WAF/CDN. |
| **DNS record** | An entry that links a name like `shop.acme.com` to an address or service. |
| **KEV** | The list of vulnerabilities that attackers are known to exploit, kept by the US agency CISA. |
| **Register** | A list you keep up to date by hand (in the `registers` folder). |
| **Scope** | The domains and addresses you own and allow TargetZero to check. |
| **Terminal** | The window where you type commands. |
