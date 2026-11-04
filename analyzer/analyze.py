"""Migration-readiness analysis for a legacy proxy -> Netskope cut-over.

Reads the CSVs produced by generator/generate_logs.py (or a real export with
the same CIM-style columns) and produces:

  output/app_readiness.csv       one row per application, with a readiness verdict
  output/control_gaps.csv        exception-hygiene and data-quality findings to escalate
  output/anomalies.csv           user/app pairs with unusual upload volume
  output/netskope_policy_plan.yaml  draft policy intents for review (NOT an importable Netskope config)
  output/report.html             one-page summary for application teams / change board

Every check here has an SPL twin in ../splunk/spl so the same logic can run in
Splunk; this Python version exists so the project runs without a Splunk licence
and so the logic is unit-testable.
"""
from __future__ import annotations

import argparse
import html
from datetime import date
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

# Thresholds are deliberately explicit: in an interview, "why 5%?" is a fair
# question, and the honest answer is "it's a starting point agreed with the
# app owner, then tuned on the pilot group".
DENY_RATE_REVIEW = 0.05          # >5% of an app's requests denied -> policy gap to review
HANDSHAKE_FAIL_REVIEW = 0.02     # >2% TLS handshake failures -> likely pinning / mTLS
UPLOAD_Z_THRESHOLD = 3.0         # robust z-score on bytes_out per user/app
UPLOAD_MIN_BYTES = 500_000       # ignore statistically odd but tiny uploads (noise floor)


def load(data_dir: Path) -> dict[str, pd.DataFrame]:
    d = {
        "proxy": pd.read_csv(data_dir / "proxy_events.csv", parse_dates=["event_time"]),
        "bypass": pd.read_csv(data_dir / "ssl_bypass_events.csv", parse_dates=["event_time"]),
        "inventory": pd.read_csv(data_dir / "lookups" / "app_inventory.csv"),
        "exceptions": pd.read_csv(data_dir / "lookups" / "bypass_exceptions.csv",
                                  parse_dates=["expires"], keep_default_na=False),
        "users": pd.read_csv(data_dir / "lookups" / "users.csv"),
    }
    d["exceptions"]["expires"] = pd.to_datetime(d["exceptions"]["expires"])
    return d


def enrich(proxy: pd.DataFrame, inventory: pd.DataFrame, users: pd.DataFrame) -> pd.DataFrame:
    """Equivalent of `| lookup app_inventory domain AS dest | lookup users user`."""
    inv = inventory.rename(columns={"domain": "dest", "business_unit": "app_bu"})
    out = proxy.merge(inv, on="dest", how="left").merge(users, on="user", how="left")
    # group unmapped traffic by registrable domain (last two labels) so
    # www.dropbox.com and content.dropboxapi.com don't look like five apps
    reg = out["dest"].str.split(".").str[-2:].str.join(".")
    out["app"] = out["app"].fillna("UNMAPPED:" + reg)
    out["owner"] = out["owner"].fillna("")
    return out


def data_quality(proxy: pd.DataFrame) -> list[dict]:
    """Checks you run BEFORE trusting any migration numbers."""
    findings = []
    required = ["event_time", "src", "user", "dest", "action", "status"]
    for col in required:
        missing = proxy[col].isna().mean()
        if missing > 0:
            findings.append({"type": "data_quality", "severity": "medium",
                             "item": col, "detail": f"{missing:.1%} of events missing '{col}'"})
    per_node = proxy.groupby("proxy_node").size()
    if len(per_node) > 1 and per_node.min() < 0.2 * per_node.max():
        findings.append({"type": "data_quality", "severity": "high", "item": "proxy_node",
                         "detail": f"Uneven log volume across nodes {per_node.to_dict()} - possible forwarder gap"})
    return findings


def exception_hygiene(exc: pd.DataFrame, bypass: pd.DataFrame, today: pd.Timestamp) -> list[dict]:
    findings = []
    used = bypass.groupby("dest").size()
    for _, e in exc.iterrows():
        hits = int(used.get(e["domain"], 0))
        if e["expires"] < today and hits:
            findings.append({"type": "control_gap", "severity": "high", "item": e["domain"],
                             "detail": f"Exception expired {e['expires'].date()} but still matched {hits} sessions"})
        elif e["expires"] < today:
            findings.append({"type": "control_gap", "severity": "low", "item": e["domain"],
                             "detail": f"Expired exception with no traffic - remove, do not migrate"})
        if not e["ticket"]:
            findings.append({"type": "control_gap", "severity": "medium", "item": e["domain"],
                             "detail": "Exception has no change ticket - no audit trail for approval"})
        if hits == 0 and e["expires"] >= today:
            findings.append({"type": "control_gap", "severity": "low", "item": e["domain"],
                             "detail": "Active exception never used in window - candidate to drop before migration"})
    # Bypassed by policy but NOT in the approved list
    approved = set(exc["domain"])
    rogue = bypass[(bypass["ssl_result"] == "bypassed") & (~bypass["dest"].isin(approved))]
    for dest, n in rogue.groupby("dest").size().items():
        findings.append({"type": "control_gap", "severity": "high", "item": dest,
                         "detail": f"{n} sessions bypassed inspection with no approved exception on file"})
    return findings


def app_readiness(ev: pd.DataFrame, bypass: pd.DataFrame, exc: pd.DataFrame, today: pd.Timestamp) -> pd.DataFrame:
    valid_exc = set(exc.loc[exc["expires"] >= today, "domain"])
    g = ev.groupby("app")
    df = pd.DataFrame({
        "owner": g["owner"].first(),
        "business_unit": g["app_bu"].first(),
        "migration_wave": g["migration_wave"].first(),
        "events": g.size(),
        "users": g["user"].nunique(),
        # policy denies only: TLS handshake failures are counted separately,
        # otherwise a pinned app looks like a policy problem when it is an inspection problem
        "deny_rate": g.apply(lambda x: ((x["action"] == "blocked") & (x["ssl_result"] != "handshake_failed")).mean(),
                             include_groups=False),
        "handshake_fail_rate": g.apply(lambda x: (x["ssl_result"] == "handshake_failed").mean(), include_groups=False),
        "bypass_rate": g.apply(lambda x: x["ssl_result"].isin(["bypassed", "not_inspected"]).mean(), include_groups=False),
        "non_std_port": g["dest_port"].apply(lambda s: bool((s != 443).any())),
        "domains": g["dest"].apply(lambda s: ",".join(sorted(s.unique()))),
        "top_deny_rule": g.apply(lambda x: x.loc[(x["action"] == "blocked") & (x["ssl_result"] != "handshake_failed"), "rule"].mode().iat[0]
                                 if ((x["action"] == "blocked") & (x["ssl_result"] != "handshake_failed")).any() else "",
                                 include_groups=False),
    })
    df["has_valid_exception"] = df["domains"].apply(lambda ds: any(d in valid_exc for d in ds.split(",")))

    def verdict(r) -> tuple[str, str]:
        actions = []
        if r.name.startswith("UNMAPPED:") or not r["owner"]:
            return "BLOCKED: no owner", "Identify owner via CMDB/ITSM; decide sanction or block before migrating"
        if r["handshake_fail_rate"] > HANDSHAKE_FAIL_REVIEW or r["bypass_rate"] > 0:
            if r["has_valid_exception"]:
                actions.append("Create SSL Decryption 'Do Not Decrypt' rule scoped to app domains (exception is current)")
            else:
                actions.append("Exception missing/expired: renew via change ticket, THEN add Do-Not-Decrypt rule")
        if r["non_std_port"]:
            actions.append("Define a Netskope service/destination profile for the non-443 port; confirm steering covers it")
        if r["deny_rate"] > DENY_RATE_REVIEW:
            actions.append(f"Review deny rule '{r['top_deny_rule']}' with owner: intended control or policy gap?")
        if not actions:
            return "READY", "Mirror allow policy in Netskope Real-time Protection; pilot with one BU"
        status = "NEEDS WORK" if any("missing/expired" in a or "policy gap" in a for a in actions) else "READY WITH POLICY"
        return status, " | ".join(actions)

    v = df.apply(verdict, axis=1, result_type="expand")
    df["status"], df["recommended_actions"] = v[0], v[1]
    order = {"BLOCKED: no owner": 0, "NEEDS WORK": 1, "READY WITH POLICY": 2, "READY": 3}
    df = df.sort_values(by=["status", "events"], key=lambda s: s.map(order) if s.name == "status" else -s)
    return df.reset_index()


def upload_anomalies(ev: pd.DataFrame) -> pd.DataFrame:
    """Robust z-score (median/MAD) of total bytes_out per user per app.
    MAD rather than stdev so one huge outlier doesn't hide itself."""
    per = ev.groupby(["app", "user"], as_index=False)["bytes_out"].sum()
    def z(s: pd.Series) -> pd.Series:
        med = s.median()
        mad = (s - med).abs().median() or 1.0
        return 0.6745 * (s - med) / mad
    per["robust_z"] = per.groupby("app")["bytes_out"].transform(z)
    hit = (per["robust_z"] > UPLOAD_Z_THRESHOLD) & (per["bytes_out"] > UPLOAD_MIN_BYTES)
    return per[hit].sort_values("robust_z", ascending=False)


def policy_plan(ready: pd.DataFrame) -> str:
    """Draft policy *intents* in YAML. Intentionally not Netskope's import format:
    real policies are built in the tenant (or via its API/Terraform provider) after
    review. This is the artefact the change board signs off."""
    lines = ["# DRAFT - for review by app owner + security. Not an importable config.",
             f"# generated: {date.today().isoformat()}", "policies:"]
    for _, r in ready.iterrows():
        if r["status"].startswith("BLOCKED"):
            continue
        doms = r["domains"].split(",")
        if "Do Not Decrypt" in r["recommended_actions"] or "Do-Not-Decrypt" in r["recommended_actions"]:
            lines += [f"  - name: ssl-dnd-{r['app'].lower().replace(' ', '-')}",
                      "    type: ssl_decryption", "    action: do_not_decrypt",
                      f"    destinations: {doms}",
                      f"    owner: {r['owner']}",
                      "    justification: certificate pinning / mutual TLS observed in proxy logs",
                      "    compensating_control: log SNI + destination; review quarterly"]
        lines += [f"  - name: rtp-allow-{r['app'].lower().replace(' ', '-')}",
                  "    type: real_time_protection", "    action: allow",
                  f"    pending_review: {str(r['status'] == 'NEEDS WORK').lower()}",
                  f"    destinations: {doms}",
                  f"    scope_business_unit: {r['business_unit']}",
                  f"    migration_wave: {int(r['migration_wave']) if pd.notna(r['migration_wave']) else 'tbd'}"]
    return "\n".join(lines) + "\n"


def html_report(ready: pd.DataFrame, gaps: pd.DataFrame, anomalies: pd.DataFrame, summary: dict) -> str:
    def table(df: pd.DataFrame, cols: list[str]) -> str:
        head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
        body = ""
        for _, r in df[cols].iterrows():
            cells = ""
            for c in cols:
                v = r[c]
                if isinstance(v, float) and c.endswith("rate"):
                    v = f"{v:.1%}"
                cls = f' class="s-{str(v).split(":")[0].split()[0].lower()}"' if c == "status" else ""
                cells += f"<td{cls}>{html.escape(str(v))}</td>"
            body += f"<tr>{cells}</tr>"
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    ready = ready.copy()
    ready["migration_wave"] = ready["migration_wave"].apply(lambda w: "" if pd.isna(w) else int(w))
    counts = ready["status"].value_counts().to_dict()
    kpis = "".join(f'<div class="kpi"><b>{v}</b><span>{html.escape(k)}</span></div>' for k, v in counts.items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Proxy Migration Readiness</title>
<style>
:root{{--bg:#fafaf7;--fg:#1d1d1b;--muted:#6b6b66;--line:#e4e2db;--ok:#2f7d4f;--warn:#b26b00;--bad:#b3261e}}
@media (prefers-color-scheme:dark){{:root{{--bg:#161614;--fg:#ecebe6;--muted:#a3a29b;--line:#34332f}}}}
body{{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0 auto;max-width:1100px;padding:24px 16px}}
h1{{font-weight:600;margin:0 0 4px}} p.m{{color:var(--muted);margin:0 0 20px}}
.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.kpi{{border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:140px}}
.kpi b{{display:block;font-size:24px}} .kpi span{{color:var(--muted);font-size:12px}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:500}} .s-ready{{color:var(--ok)}} .s-needs{{color:var(--warn)}} .s-blocked{{color:var(--bad)}}
h2{{font-size:16px;margin:28px 0 8px}}
</style></head><body>
<h1>Proxy &rarr; Netskope migration readiness</h1>
<p class="m">{summary['events']:,} proxy events &middot; {summary['bypass']:,} SSL-bypass sessions &middot; {summary['start']} to {summary['end']} &middot; synthetic data</p>
<div class="kpis">{kpis}</div>
<h2>Application readiness</h2><div class="wrap">{table(ready, ['app','owner','migration_wave','events','users','deny_rate','handshake_fail_rate','status','recommended_actions'])}</div>
<h2>Control gaps and data-quality findings to escalate</h2><div class="wrap">{table(gaps, ['severity','type','item','detail']) if len(gaps) else '<p>None.</p>'}</div>
<h2>Upload anomalies (robust z &gt; {UPLOAD_Z_THRESHOLD})</h2><div class="wrap">{table(anomalies.head(15), ['app','user','bytes_out','robust_z']) if len(anomalies) else '<p>None.</p>'}</div>
</body></html>"""


def run(data_dir: Path, out_dir: Path, today: pd.Timestamp | None = None) -> dict:
    today = today or pd.Timestamp("2026-11-03")
    d = load(data_dir)
    ev = enrich(d["proxy"], d["inventory"], d["users"])
    ready = app_readiness(ev, d["bypass"], d["exceptions"], today)
    gaps = pd.DataFrame(data_quality(d["proxy"]) + exception_hygiene(d["exceptions"], d["bypass"], today))
    if len(gaps):
        sev = {"high": 0, "medium": 1, "low": 2}
        gaps = gaps.sort_values("severity", key=lambda s: s.map(sev))
    anomalies = upload_anomalies(ev)
    anomalies["robust_z"] = anomalies["robust_z"].round(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    ready.to_csv(out_dir / "app_readiness.csv", index=False)
    gaps.to_csv(out_dir / "control_gaps.csv", index=False)
    anomalies.to_csv(out_dir / "anomalies.csv", index=False)
    (out_dir / "netskope_policy_plan.yaml").write_text(policy_plan(ready))
    summary = {"events": len(d["proxy"]), "bypass": len(d["bypass"]),
               "start": d["proxy"]["event_time"].min().date(), "end": d["proxy"]["event_time"].max().date()}
    (out_dir / "report.html").write_text(html_report(ready, gaps, anomalies, summary))
    return {"ready": ready, "gaps": gaps, "anomalies": anomalies}


def main() -> None:
    ap = argparse.ArgumentParser(description="Proxy migration readiness analysis")
    ap.add_argument("--data", default=str(ROOT / "sample_data"))
    ap.add_argument("--out", default=str(ROOT / "output"))
    a = ap.parse_args()
    r = run(Path(a.data), Path(a.out))
    print(r["ready"][["app", "status", "events", "deny_rate", "handshake_fail_rate"]].to_string(index=False))
    print(f"\n{len(r['gaps'])} control/data-quality findings, {len(r['anomalies'])} anomalies -> {a.out}")


if __name__ == "__main__":
    main()
