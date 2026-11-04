# Proxy → Netskope migration runbook (per application wave)

## 0. Trust the data first
- Run `10_data_quality.spl`. Any proxy node with a volume drop or missing `user` field invalidates the baseline. Fix the feed, then re-baseline.

## 1. Discover (2–4 weeks of logs)
- `01_baseline_by_app.spl` — events, users, hosts, ports, deny %, TLS-failure %, uninspected % per app.
- Map unmapped domains to an owner through the CMDB / ITSM. No owner → no migration.

## 2. Classify each app
| Signal | Meaning | Netskope action |
|---|---|---|
| Many users fail TLS handshake on same domain | Certificate pinning | SSL Decryption policy: Do Not Decrypt, scoped to domains; needs a current approved exception |
| Bypass reason = mutual TLS | Client-cert auth | Do Not Decrypt; compensating logging on SNI/destination |
| Port ≠ 443 | Non-standard port | Service / destination profile; confirm steering covers it |
| High deny % on one rule | Intended control or policy gap | Owner decision **before** recreating the rule |
| Clean | — | Mirror allow in Real-time Protection policy |

## 3. Exception hygiene (before migrating any exception)
- `05_exception_hygiene.spl`, `06_unapproved_bypass.spl`.
- Expired-and-used → renew through change management or remove.
- Unused → do not migrate.
- No ticket → escalate as an audit-trail gap.

## 4. Build and test
- Draft policy intents (`output/netskope_policy_plan.yaml`) → review with app owner and security → build in tenant.
- Pilot group (one business unit / test users), then expand.
- Test cases: login, core transaction, file upload/download, API calls, any thick client.

## 5. Cut-over and hyper-care
- Change ticket with rollback = revert steering for the pilot group to the legacy proxy (PAC file / steering configuration).
- Watch `08_hourly_trend_timechart.spl` and `09_pre_post_cutover_compare.spl`: denies, TLS failures, 5xx, before vs after.
- Go/no-go criterion agreed in advance (example: error rate within +0.5 pp of baseline for 48 h).

## 6. Close
- Decommission the legacy rule only after the Netskope equivalent has run clean through hyper-care.
- Record exceptions carried over with owner, justification, expiry, ticket.
