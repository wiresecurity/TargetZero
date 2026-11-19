# External checks

These run from your own machine and talk to the internet. They only touch what is in `scope` in `targetzero.yaml`.

## `targetzero external scan` (Zero 4)

Open TCP ports on your public IP ranges, compared with `registers/approved_exposure.csv`.

```bash
targetzero external scan --authorised            # nmap if installed, otherwise the built-in scanner
targetzero external scan --authorised --internetdb   # also ask Shodan InternetDB (free, no key)
```

- **Run it from outside your network**: a small cloud VM or a home line. From inside you see your LAN, not what the internet sees.
- `--authorised` is required: you confirm that you own, or may scan, every address in `scope.ip_ranges`.
- Hostnames in `scope.domains` and the inventory are resolved. Their addresses are scanned only when they fall inside `scope.ip_ranges`; a site behind a CDN is not yours to scan.
- About 50 ports are checked: remote administration, firewall and VPN admin pages, file sharing, databases, mail and web.
- An open port counts when it is not on the approved list. Ports that only InternetDB reports are listed, not counted: its data can be a week old.

## `targetzero external discover` (Zero 5)

Finds your public names and addresses and merges them into `registers/inventory.csv`.

```bash
targetzero external discover
targetzero external discover --zone-file example.com.zone:example.com
```

Sources: `scope.domains`, the domain lists written today by `Get-T0M365Domain` and `targetzero gws domains`, zone files, and certificate transparency logs (crt.sh). New rows are added as *unreviewed*; columns you filled in are never changed. A backup of the register is kept next to it.

Then fill in owner, purpose, product, version and vendor support for each row, set `status` to `reviewed` and `last_reviewed` to today, and count again:

```bash
targetzero registers inventory
```

## `targetzero external kev` (Zero 6)

Matches the CISA Known Exploited Vulnerabilities catalog against the products in the inventory and the firmware versions found by the vendor collectors today.

```bash
targetzero external kev
NVD_API_KEY=... targetzero external kev      # faster NVD lookups (free key from nvd.nist.gov)
```

- With a **version** in the inventory, the NVD API tells whether that version is affected; entries that do not apply are dropped.
- Without a version, only KEV entries from the last 30 days (`--recent-days`) are reported, with a note to confirm.
- With `--internetdb` scan data from today, CVEs that InternetDB reports for your addresses are matched too.
- New findings go into `registers/findings.csv` with a deadline (KEV: 8 hours after it was added to the catalog). Rows you updated are never changed. Set `status` to `patched` or `mitigated` when done, then recount with `targetzero registers findings`.

## `targetzero external waf` (Zero 4)

Checks that every web name in scope resolves into a known WAF/CDN: Cloudflare, CloudFront and Fastly by their published IP ranges; Akamai, Azure Front Door, Imperva and Sucuri by CNAME.

```bash
targetzero external waf
targetzero external waf --authorised     # also test origins
```

- A name counts when it serves web traffic (port 443 or 80 open) and is not behind a known provider.
- Set `behind_waf` to `n/a` in the inventory for names that are not websites (a VPN portal, a mail server); they are skipped.
- To check that an origin server refuses direct traffic, list it in `registers/origins.csv` (`host,origin_ip`). With `--authorised`, TargetZero connects to the origin address with the site's name. An answer means the origin can be reached around the WAF, which counts. Only origins inside `scope.ip_ranges` are tested.

## `targetzero external enrich` (Zero 5)

Probes every in-scope inventory asset once and writes suggestions to `output/<date>/5_external_enrich.csv`: TLS version and certificate, `Server` and `X-Powered-By` headers, product and version (also from InternetDB CPEs), and support status from endoflife.date for nginx, Apache, PHP, Tomcat, OpenSSL and Node.js. The inventory itself is not changed; copy what is right.

## `targetzero external dangling-dns` (Zero 5)

Finds names whose CNAME points to something that no longer exists, or to an unclaimed bucket, app or page (Amazon S3, GitHub Pages, Heroku, Azure App Service, Shopify, Zendesk, Fastly, Surge) that someone else could take over. Each one counts until the DNS record is deleted. Names come from the inventory and today's discovery. A records pointing to released cloud addresses are not detected.
