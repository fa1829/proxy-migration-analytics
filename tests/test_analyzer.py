"""Tests pin the behaviours an interviewer would probe: does the tool tell a
pinned app apart from a policy gap, and does it catch exception-hygiene problems?"""
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "generator"))
sys.path.insert(0, str(ROOT / "analyzer"))

import analyze  # noqa: E402
import generate_logs  # noqa: E402


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")
    out = tmp_path_factory.mktemp("out")
    generate_logs.generate(data, days=3, events_per_day=2000, seed=11)
    return analyze.run(data, out, today=pd.Timestamp("2026-11-03")), out


def status_of(ready, app):
    return ready.set_index("app").loc[app, "status"]


def test_outputs_written(result):
    _, out = result
    for f in ["app_readiness.csv", "control_gaps.csv", "anomalies.csv", "netskope_policy_plan.yaml", "report.html"]:
        assert (out / f).stat().st_size > 0


def test_pinned_app_with_valid_exception_is_not_a_policy_gap(result):
    ready = result[0]["ready"].set_index("app")
    bb = ready.loc["Bloomberg Terminal"]
    assert bb["handshake_fail_rate"] > 0.3
    assert bb["deny_rate"] == 0          # handshake failures are not counted as policy denies
    assert bb["status"] == "READY WITH POLICY"
    assert "Do Not Decrypt" in bb["recommended_actions"]


def test_pinned_app_with_expired_exception_needs_work(result):
    assert status_of(result[0]["ready"], "Zoom") == "NEEDS WORK"


def test_noisy_deny_app_flagged_for_rule_review(result):
    ready = result[0]["ready"].set_index("app")
    assert ready.loc["GitHub", "status"] == "NEEDS WORK"
    assert "deny-dev-tools" in ready.loc["GitHub", "recommended_actions"]


def test_shadow_it_has_no_owner(result):
    ready = result[0]["ready"]
    unmapped = ready[ready["app"].str.startswith("UNMAPPED:")]
    assert set(unmapped["status"]) == {"BLOCKED: no owner"}
    assert "UNMAPPED:dropbox.com" in set(unmapped["app"])


def test_clean_saas_is_ready(result):
    assert status_of(result[0]["ready"], "Office 365") == "READY"


def test_exception_hygiene_findings(result):
    gaps = result[0]["gaps"]
    details = " ".join(gaps["detail"])
    assert "expired 2026-09-30 but still matched" in details      # zoom.us
    assert "no change ticket" in details                           # fx feed
    assert "no approved exception on file" in details              # us04web.zoom.us
    assert set(gaps.loc[gaps["item"] == "zoom.us", "severity"]) == {"high"}


def test_planted_exfil_user_is_top_anomaly(result):
    anomalies = result[0]["anomalies"]
    assert anomalies.iloc[0]["user"] == "u0042"


def test_policy_plan_skips_unowned_apps(result):
    _, out = result
    plan = (out / "netskope_policy_plan.yaml").read_text()
    assert "dropbox" not in plan.lower()
    assert "ssl-dnd-bloomberg-terminal" in plan


def test_uneven_node_volume_detected():
    df = pd.DataFrame({"event_time": pd.date_range("2026-10-01", periods=110, freq="h"),
                       "src": "10.0.0.1", "user": "u1", "dest": "x.com", "action": "allowed", "status": 200,
                       "proxy_node": ["a"] * 100 + ["b"] * 10})
    f = analyze.data_quality(df)
    assert any(x["item"] == "proxy_node" and x["severity"] == "high" for x in f)
