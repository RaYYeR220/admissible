"""The demo, run as a test, because it must never flake.

The demo is the thing a judge watches. If a beat can come out differently
between two runs, or between two machines, that is the worst possible place to
find out. So the scenario is executed here in full -- as subprocesses, exactly
as a viewer runs it -- and the outcome of every beat is asserted against its
JSON, twice, to catch anything order- or clock-dependent.

These are the slowest tests in the suite. They earn it: they are the only ones
that check the artefact that actually gets shown.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = _REPO_ROOT / "scripts" / "demo.py"


def run_demo(db: Path, *args: str) -> dict:
    """Invoke the demo as a separate process and parse its JSON report."""
    completed = subprocess.run(
        [sys.executable, str(DEMO), "--db", str(db), "--offline", "--json", *args],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        # A clean environment: the default demo must not change behaviour
        # because a key happens to be exported on the machine running it.
        env={
            k: v
            for k, v in __import__("os").environ.items()
            if k not in ("VENICE_API_KEY", "VENICE_MODEL")
        },
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout)


@pytest.fixture(scope="module")
def session_one(tmp_path_factory) -> tuple[Path, dict]:
    db = tmp_path_factory.mktemp("demo") / "admissible-demo.db"
    return db, run_demo(db, "--session", "1")


def _beat(report: dict, name: str) -> dict:
    return next(b for b in report["beats"] if b.get("name") == name)


def test_beat_1_pays_the_counterparty_whose_history_re_derives(session_one) -> None:
    _, report = session_one
    control = _beat(report, "negative_control")
    assert control["ok"] and control["got"] == "pay"
    assert control["run"]["receipt"]["settled"] is True
    assert control["run"]["receipt"]["amount_usd"] == pytest.approx(0.25)
    assert len(control["run"]["citations"]) == 3


def test_beat_2_writes_three_distinct_vectors_into_the_same_store(session_one) -> None:
    _, report = session_one
    vectors = _beat(report, "attack")["vectors"]
    assert [v["vector"] for v in vectors] == [
        "poisoned_job_result",
        "peer_reference",
        "tool_output_injection",
    ]
    assert len({v["expected_verdict"] for v in vectors}) == 3
    assert len({v["source"] for v in vectors}) == 3


def test_beat_3_refuses_outright_on_evidence_not_found(session_one) -> None:
    """Not escrow. Collateral protects against failure, not against fraud."""
    _, report = session_one
    refusal = _beat(report, "refusal")
    assert refusal["ok"] and refusal["got"] == "refuse"
    assert refusal["evidence_not_found_present"] is True
    assert refusal["run"]["blocked_by"]["kind"] == "laundering_attempt"
    assert refusal["run"]["blocked_by"]["verdict"] == "evidence_not_found"
    assert refusal["run"]["receipt"]["settled"] is False


def test_beat_3_flags_the_forger_with_its_address_and_its_evidence(session_one) -> None:
    _, report = session_one
    refusal = _beat(report, "refusal")
    assert len(refusal["flags_raised"]) == 1
    flag = refusal["flags_raised"][0]
    assert flag["actor_address"]
    assert flag["digest"].startswith("0x")
    assert refusal["contaminated"], "the ring walk must reach at least the accomplice"


def test_beat_3_posture_probe_flips_the_action(session_one) -> None:
    """The reflection claim, stated as a before and after on one request."""
    _, report = session_one
    probe = _beat(report, "refusal")["posture_probe"]
    assert probe["before"]["action"] == "escrow"
    assert probe["after"]["action"] == "refuse"
    assert probe["after"]["stranger_ceiling_usd"] == 0.0


def test_session_2_is_a_different_process_and_refuses_on_sight(session_one) -> None:
    db, first = session_one
    second = run_demo(db, "--session", "2")

    assert second["pid"] != first["pid"], "the point of the beat is a new process"
    assert second["verdict"]["refused_on_sight"] is True
    assert second["verdict"]["flags_at_cold_start"] == 2
    returning = _beat(second, "returning_poisoner")
    assert returning["run"]["receipt"]["settled"] is False
    assert all(c["verdict"]["admits"] for c in returning["run"]["considered"]), (
        "the planted memories are admitted; the refusal is about the counterparty"
    )


def test_the_deletion_test_lets_the_attack_through(session_one) -> None:
    """The disqualification test, and it has to actually be destructive."""
    db, _ = session_one
    deleted = run_demo(db, "--delete-memory")
    verdict = deleted["verdict"]

    assert verdict["flags_at_first_contact"] == 0
    assert verdict["returning_poisoner_action"] == "pay"
    assert verdict["returning_poisoner_settled_usd"] == pytest.approx(0.25)
    # The half that is easy to forget: memory is revenue as well as defence.
    assert verdict["honest_counterparty_action"] == "escrow"
    # And the half that survives, stated rather than hidden.
    assert verdict["forged_settlement_action"] == "refuse"


def test_the_scenario_is_reproducible(tmp_path) -> None:
    """Two independent runs, same outcomes. Anything that depends on row order,
    on the wall clock, or on what the last run left behind shows up here."""
    first = run_demo(tmp_path / "a.db", "--session", "1")
    second = run_demo(tmp_path / "b.db", "--session", "1")

    def shape(report: dict) -> list:
        return [
            (b.get("name"), b.get("got"), b.get("ok"))
            for b in report["beats"]
            if b.get("name") in ("negative_control", "refusal")
        ]

    assert shape(first) == shape(second)
    assert first["verdict"] == second["verdict"]


def test_the_default_invocation_runs_the_whole_story(tmp_path) -> None:
    """One command, three processes, five beats. What a judge actually types."""
    report = run_demo(tmp_path / "full.db")
    assert report["session"] == 1
    assert len(report["children"]) == 2

    pids = {report["pid"]} | {
        child["report"]["pid"] for child in report["children"] if "report" in child
    }
    assert len(pids) == 3, "each session must be a genuinely separate process"

    sessions = [child["report"]["session"] for child in report["children"]]
    assert sessions == [2, 5]
    assert report["children"][1]["report"]["verdict"]["returning_poisoner_action"] == "pay"
