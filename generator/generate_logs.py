"""Generate synthetic legacy-proxy and SSL-inspection-bypass logs for a
proxy -> Netskope migration exercise.

Everything here is invented. Domains use real SaaS names only so the data
looks familiar; no real traffic, users or company data is involved.

Outputs (in --out, default ./sample_data):
  proxy_events.csv          one row per web transaction seen by the legacy proxy
  ssl_bypass_events.csv     one row per TLS session the proxy did NOT decrypt
  lookups/app_inventory.csv  app -> owner, business unit, domains, migration wave
  lookups/bypass_exceptions.csv  approved SSL-inspection exceptions (some expired)
  lookups/users.csv         user -> business unit, department

Field names follow the Splunk Common Information Model (CIM) "Web" data model
(src, user, url, dest, http_method, status, action, bytes_in/bytes_out,
http_user_agent, category) so the SPL in ../splunk/spl works unchanged once the
CSVs are indexed with a sourcetype that keeps these headers.
"""
from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# --------------------------------------------------------------------------
# Reference data: applications, their domains, owners and quirks
# --------------------------------------------------------------------------
# quirk:
#   normal          decrypts fine, mostly allowed
#   cert_pinned     breaks under TLS interception -> handshake failures, needs Do-Not-Decrypt
#   mtls            client-certificate auth -> cannot be inspected
#   noisy_denied    frequently hits deny rules (mis-categorised / policy gap)
#   non_std_port    talks on a non-443 port; Netskope needs a service profile
#   shadow          not in the inventory at all (unowned traffic)
APPS = [
    # app,                 domains,                                       owner,          bu,               wave, quirk
    ("Office 365",        ["outlook.office365.com", "login.microsoftonline.com", "graph.microsoft.com"], "it.collab", "Corporate IT", 1, "normal"),
    ("Salesforce",        ["acme.my.salesforce.com", "login.salesforce.com"],     "crm.team",     "Retail Banking", 1, "normal"),
    ("ServiceNow",        ["acme.service-now.com"],                               "itsm.team",    "Corporate IT",   1, "normal"),
    ("Bloomberg Terminal",["bpipe.bloomberg.net", "bba.bloomberg.net"],           "mkt.data",     "Capital Markets",2, "cert_pinned"),
    ("Zoom",              ["zoom.us", "us04web.zoom.us"],                         "it.collab",    "Corporate IT",   1, "cert_pinned"),
    ("SWIFT Alliance",    ["swiftnet.swift.com"],                                 "payments.ops", "Payments",       3, "mtls"),
    ("Refinitiv Eikon",   ["api.refinitiv.com", "eikon.refinitiv.com"],           "mkt.data",     "Capital Markets",2, "normal"),
    ("GitHub",            ["github.com", "api.github.com", "objects.githubusercontent.com"], "devtools", "Technology", 2, "noisy_denied"),
    ("Docker Hub",        ["registry-1.docker.io", "auth.docker.io"],             "devtools",     "Technology",     2, "noisy_denied"),
    ("Vendor FX Feed",    ["fx.vendorfeed.example:8443"],                         "fx.desk",      "Capital Markets",3, "non_std_port"),
    ("Workday",           ["wd5.myworkday.com"],                                  "hr.systems",   "Human Resources",1, "normal"),
    ("Dropbox",           ["www.dropbox.com", "content.dropboxapi.com"],          None,           None,             None, "shadow"),
    ("Pastebin",          ["pastebin.com"],                                       None,           None,             None, "shadow"),
]

CATEGORIES = {
    "Office 365": "Business and Economy", "Salesforce": "Business and Economy",
    "ServiceNow": "Computer and Internet Info", "Bloomberg Terminal": "Financial Services",
    "Zoom": "Internet Communications", "SWIFT Alliance": "Financial Services",
    "Refinitiv Eikon": "Financial Services", "GitHub": "Computer and Internet Info",
    "Docker Hub": "Computer and Internet Info", "Vendor FX Feed": "Unknown",
    "Workday": "Business and Economy", "Dropbox": "Online Storage and Backup",
    "Pastebin": "Questionable",
}

BUS = ["Retail Banking", "Capital Markets", "Payments", "Technology", "Corporate IT", "Human Resources"]
AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "python-requests/2.32.3",
    "curl/8.7.1",
    "BloombergTerminal/1.0",
    "ZoomClient/6.2",
]


def build_users(n: int, rng: random.Random) -> list[dict]:
    users = []
    for i in range(n):
        bu = rng.choice(BUS)
        users.append({
            "user": f"u{i:04d}",
            "business_unit": bu,
            "department": f"{bu.split()[0].lower()}-{rng.randint(1, 4)}",
            "src": f"10.{BUS.index(bu) + 10}.{rng.randint(0, 31)}.{rng.randint(2, 254)}",
        })
    return users


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def generate(out: Path, days: int, events_per_day: int, seed: int) -> dict:
    rng = random.Random(seed)
    users = build_users(400, rng)
    start = datetime(2026, 10, 1)

    # Weighted app popularity: SaaS heavy, specialist apps light, shadow small.
    weights = [30, 12, 8, 4, 10, 1, 4, 8, 4, 1, 5, 2, 0.4]

    proxy_rows, bypass_rows = [], []
    for d in range(days):
        day = start + timedelta(days=d)
        for _ in range(events_per_day):
            app, domains, owner, bu, wave, quirk = rng.choices(APPS, weights=weights)[0]
            u = rng.choice(users)
            # business hours bias
            hour = int(rng.triangular(6, 20, 11)) if rng.random() < 0.9 else rng.randint(0, 23)
            ts = day + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            host = rng.choice(domains)
            port = 443
            if ":" in host:
                host, port = host.split(":")[0], int(host.split(":")[1])
            method = rng.choices(["GET", "POST", "PUT", "CONNECT"], weights=[60, 30, 5, 5])[0]
            action, status, ssl_result, rule = "allowed", 200, "decrypted", "allow-business-saas"

            if quirk == "cert_pinned":
                if rng.random() < 0.55:  # inspection breaks the pinned client
                    action, status, ssl_result, rule = "blocked", 0, "handshake_failed", "ssl-inspect-default"
                else:
                    ssl_result, rule = "bypassed", "ssl-bypass-financial"
            elif quirk == "mtls":
                ssl_result, rule = "bypassed", "ssl-bypass-mtls"
            elif quirk == "noisy_denied" and rng.random() < 0.35:
                action, status, rule = "blocked", 403, "deny-dev-tools"
            elif quirk == "non_std_port":
                ssl_result, rule = "not_inspected", "allow-fx-vendor-port"
            elif quirk == "shadow":
                if app == "Pastebin":
                    action, status, rule = "blocked", 403, "deny-questionable"
                else:
                    rule = "allow-default-web"
            # small random noise of upstream errors
            if action == "allowed" and rng.random() < 0.02:
                status = rng.choice([502, 503, 504])

            bytes_out = int(rng.lognormvariate(7, 1.2))
            bytes_in = int(rng.lognormvariate(9, 1.5))
            # one exfil-looking anomaly: a single user pushing a lot to Dropbox
            if app == "Dropbox" and u["user"] == "u0042":
                bytes_out *= 400

            ua = rng.choice(AGENTS)
            if app == "Bloomberg Terminal":
                ua = "BloombergTerminal/1.0"
            if app == "Zoom":
                ua = "ZoomClient/6.2"

            row = {
                "_time": ts.isoformat(timespec="seconds"),
                "src": u["src"], "user": u["user"],
                "dest": host, "dest_port": port,
                "url": f"https://{host}{'' if port == 443 else ':' + str(port)}/{rng.choice(['', 'api/v1/', 'login', 'data/stream'])}",
                "http_method": method, "status": status, "action": action,
                "category": CATEGORIES[app], "rule": rule,
                "ssl_result": ssl_result,
                "bytes_in": bytes_in, "bytes_out": bytes_out,
                "http_user_agent": ua,
                "proxy_node": rng.choice(["mtl-swg-01", "mtl-swg-02", "tor-swg-01"]),
            }
            proxy_rows.append(row)

            if ssl_result in ("bypassed", "handshake_failed", "not_inspected"):
                reason = {
                    "bypassed": "policy_exception",
                    "handshake_failed": rng.choice(["unknown_ca", "certificate_pinning", "client_alert_bad_certificate"]),
                    "not_inspected": "non_standard_port",
                }[ssl_result]
                bypass_rows.append({
                    "_time": row["_time"], "src": row["src"], "user": row["user"],
                    "dest": host, "dest_port": port,
                    "sni": host, "tls_version": rng.choice(["TLSv1.2", "TLSv1.3", "TLSv1.3"]),
                    "ssl_result": ssl_result, "bypass_reason": reason,
                    "rule": rule, "proxy_node": row["proxy_node"],
                })

    proxy_rows.sort(key=lambda r: r["_time"])
    bypass_rows.sort(key=lambda r: r["_time"])

    write_csv(out / "proxy_events.csv", proxy_rows, list(proxy_rows[0].keys()))
    write_csv(out / "ssl_bypass_events.csv", bypass_rows, list(bypass_rows[0].keys()))

    inv = []
    for app, domains, owner, bu, wave, quirk in APPS:
        if quirk == "shadow":
            continue  # shadow apps are by definition missing from the inventory
        for dom in domains:
            inv.append({"app": app, "domain": dom.split(":")[0], "owner": owner,
                        "business_unit": bu, "migration_wave": wave})
    write_csv(out / "lookups" / "app_inventory.csv", inv, list(inv[0].keys()))

    exceptions = [
        # domain, reason, approver, ticket, expires
        ("bpipe.bloomberg.net", "certificate_pinning", "ciso.delegate", "CHG0012001", "2027-03-31"),
        ("bba.bloomberg.net",  "certificate_pinning", "ciso.delegate", "CHG0012001", "2027-03-31"),
        ("swiftnet.swift.com", "mutual_tls",          "ciso.delegate", "CHG0010555", "2026-12-31"),
        ("zoom.us",            "certificate_pinning", "it.collab.mgr", "CHG0009870", "2026-09-30"),  # expired
        ("fx.vendorfeed.example", "non_standard_port", "fx.desk.head", "",          "2026-06-30"),  # expired, no ticket
        ("old-hr-portal.example", "legacy_app",       "hr.systems",   "CHG0007001", "2025-12-31"),  # stale, unused
    ]
    write_csv(out / "lookups" / "bypass_exceptions.csv",
              [dict(zip(["domain", "reason", "approver", "ticket", "expires"], e)) for e in exceptions],
              ["domain", "reason", "approver", "ticket", "expires"])
    write_csv(out / "lookups" / "users.csv",
              [{k: u[k] for k in ("user", "business_unit", "department")} for u in users],
              ["user", "business_unit", "department"])
    return {"proxy_events": len(proxy_rows), "ssl_bypass_events": len(bypass_rows)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "sample_data"))
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--events-per-day", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    counts = generate(Path(a.out), a.days, a.events_per_day, a.seed)
    print(f"Wrote {counts} to {a.out}")


if __name__ == "__main__":
    main()
