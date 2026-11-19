---
app_id: ""          # id of the inventory row, e.g. inventory:shop.example.com
application: ""
owner: ""
status: draft       # draft | complete | tested
shutdown_tested: "" # YYYY-MM-DD of the last shutdown test
last_reviewed: ""   # YYYY-MM-DD
---

# Recovery page: <application>

Hostnames:
Hosted by:
Vendor or provider contact (including after hours):

## 1. Shut down (target: under 15 minutes)

| Question | Answer |
| --- | --- |
| Who decides? | |
| Who executes? | |
| How (firewall rule, DNS change, hosting panel, kill switch)? | |
| Phone numbers, including after hours | |
| Last tested on | |

## 2. Rotate secrets (target: under 24 hours)

| Secret (password, API key, certificate, service account) | Used for | Who can change it | Order |
| --- | --- | --- | --- |
| | | | |

## 3. Rebuild (target: within the agreed recovery time)

| Question | Answer |
| --- | --- |
| Agreed recovery time | |
| Where are the backups? | |
| Where is the configuration? | |
| Last tested restore | |
| Who can rebuild it? | |

## 4. Change crypto (target: under 30 days)

| Question | Answer |
| --- | --- |
| Certificates in use (issuer, expiry, key type and size) | |
| TLS versions and settings | |
| Who can change them? | |
| Does the vendor support newer algorithms? | |

A plan that has never been tested counts as missing.
