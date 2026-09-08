"""The command line, exercised the way a judge would run it.

Offline, keyless, one database per test, and never the developer's own store:
every case passes ``--db`` and the environment is scrubbed of the variables that
would otherwise redirect it. The two properties that matter most here are the
exit codes -- an inadmissible memory must not exit 0 -- and the refusal to
publish an anchor without a key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from admissible import cli
from admissible.envelope import Envelope, Evidence, Tier
from admissible.store import AdmissibleStore

from conftest import envelope  # noqa: E402 - the suite's own fixtures module

COUNTERPARTY = "0x4069ef1afc8a9b2a29117a3740fcab2912499fbe"
STRANGER = "0x000000000000000000000000000000000000dead"
FAKE_TX = "0x" + "22" * 32
#: Not a key to anything. Present only so the "no key" refusal can be told apart
#: from the "no anchor address" one.
DUMMY_KEY = "0x" + "11" * 32

#: Environment that would otherwise point the CLI somewhere real.
_LEAKY = (
    "ADMISSIBLE_DB",
    "SIBYL_MEMORY_DB",
    "SIBYL_TENANT_ID",
    "BASE_RPC_URL",
    "PRIVATE_KEY",
    "ANCHOR_ADDRESS",
    "ADMISSIBLE_SELF_ADDRESS",
    "ADMISSIBLE_CATEGORIES",
    "NO_COLOR",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in _LEAKY:
        monkeypatch.delenv(name, raising=False)


class NoSuchTransaction:
    """A chain that answers honestly and says the transaction is not there.

    Distinct from having no reader at all: "not found" is the chain speaking,
    and it is what a fabricated receipt looks like.
    """

    def verify_settlement(self, tx_hash: str, chain_id: int):
        return None

    def read_feedback_hash(self, registry, agent_id, feedback_index, chain_id):
        return None


@pytest.fixture()
def offline_chain(monkeypatch):
    """Give the CLI a chain reader without a network, for the forgery paths."""
    monkeypatch.setattr(
        cli, "_chain", lambda args: (NoSuchTransaction(), "canned chain reader")
    )


def seed(db: Path, *memories: tuple[str, str, Envelope]) -> None:
    """Write memories, then close: the CLI opens the file for itself."""
    store = AdmissibleStore.open(db)
    try:
        for category, name, env in memories:
            store.remember(category, name, env)
    finally:
        store.close()


def run(db: Path, *argv: str) -> int:
    return cli.main(["--db", str(db), *argv])


def run_json(db: Path, capsys, *argv: str) -> tuple[int, dict]:
    code = run(db, "--json", *argv)
    return code, json.loads(capsys.readouterr().out)


def witnessed(amount: str = "1.00", counterparty: str = COUNTERPARTY) -> Envelope:
    return envelope({"counterparty": counterparty, "amount_usd": amount})


def forged(counterparty: str = COUNTERPARTY) -> Envelope:
    return envelope(
        {"counterparty": counterparty, "amount_usd": "900.00"},
        tier=Tier.ATTESTED,
        source="peer:reference",
        actor_address=STRANGER,
        evidence=Evidence(chain_id=8453, tx_hash=FAKE_TX, kind="x402:settlement"),
    )


# ----------------------------------------------------------------------
# verify
# ----------------------------------------------------------------------
def test_verify_admits_a_first_party_observation_and_exits_zero(db_path, capsys):
    seed(db_path, ("interaction", "job-1", witnessed()))
    code = run(db_path, "verify", "interaction", "job-1")
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "ADMISSIBLE" in out
    assert "interaction/job-1" in out


def test_verify_exits_non_zero_on_an_inadmissible_memory(db_path, capsys):
    """The load-bearing exit code: hearsay must never look like success."""
    seed(
        db_path,
        (
            "testimonial",
            "boast",
            envelope(
                {"counterparty": COUNTERPARTY, "summary": "delivered 12 times"},
                tier=Tier.HEARSAY,
                source="peer:reference",
                actor_address=STRANGER,
            ),
        ),
    )
    code = run(db_path, "verify", "testimonial", "boast")
    out = capsys.readouterr().out
    assert code == cli.EXIT_REFUSED
    assert code != 0
    assert "INADMISSIBLE" in out
    assert "inadmissible_hearsay" in out


def test_verify_json_carries_the_verdict_and_the_claim_together(db_path, capsys):
    seed(db_path, ("interaction", "job-1", witnessed()))
    code, payload = run_json(db_path, capsys, "verify", "interaction", "job-1")
    assert code == cli.EXIT_OK
    assert payload["verdict"]["code"] == "admissible"
    assert payload["claim"]["counterparty"] == COUNTERPARTY
    assert payload["digest"].startswith("0x")


def test_verify_of_a_memory_that_is_not_there_is_a_sentence_not_a_traceback(
    db_path, capsys
):
    code = run(db_path, "verify", "interaction", "never-written")
    captured = capsys.readouterr()
    assert code == cli.EXIT_NOT_FOUND
    assert captured.err.startswith("admissible: There is no memory")
    assert "Traceback" not in captured.err


# ----------------------------------------------------------------------
# decide
# ----------------------------------------------------------------------
def test_decide_pays_when_first_hand_history_covers_the_request(db_path, capsys):
    seed(db_path, ("interaction", "job-1", witnessed("1.00")))
    code, payload = run_json(db_path, capsys, "decide", COUNTERPARTY, "0.20")
    assert code == cli.EXIT_OK
    assert payload["action"] == "pay"
    assert payload["citations"], "a payment must name what justified it"


def test_decide_escrows_when_the_history_falls_short(db_path, capsys):
    seed(db_path, ("interaction", "job-1", witnessed("1.00")))
    code, payload = run_json(db_path, capsys, "decide", COUNTERPARTY, "5.00")
    assert code == cli.EXIT_CONDITIONAL
    assert payload["action"] == "escrow"
    assert payload["collateral_usd"] > 0


def test_decide_refuses_and_exits_non_zero_on_a_fabricated_receipt(
    db_path, capsys, offline_chain
):
    seed(
        db_path,
        ("interaction", "job-1", witnessed("1.00")),
        ("testimonial", "forged", forged()),
    )
    code, payload = run_json(db_path, capsys, "decide", COUNTERPARTY, "0.20")
    assert code == cli.EXIT_REFUSED
    assert payload["action"] == "refuse"
    assert payload["blocked_by"]["verdict"] == "evidence_not_found"
    # The refused memory is listed with its location, not quietly dropped.
    refused = [c for c in payload["considered"] if not c["verdict"]["admits"]]
    assert refused[0]["category"] == "testimonial"
    assert refused[0]["name"] == "forged"


def test_decide_shows_the_citations_and_the_refusals_in_the_human_rendering(
    db_path, capsys, offline_chain
):
    seed(
        db_path,
        ("interaction", "job-1", witnessed("1.00")),
        ("testimonial", "forged", forged()),
    )
    run(db_path, "decide", COUNTERPARTY, "0.20")
    out = capsys.readouterr().out
    assert "REFUSE" in out
    assert "evidence_not_found" in out
    assert "citations" in out


# ----------------------------------------------------------------------
# flags
# ----------------------------------------------------------------------
def test_flags_on_a_clean_store_says_so_and_exits_zero(db_path, capsys):
    code = run(db_path, "flags")
    assert code == cli.EXIT_OK
    assert "No flagged actors" in capsys.readouterr().out


def test_flags_lists_the_tier_and_exits_non_zero_when_anybody_is_flagged(
    db_path, capsys
):
    from admissible.flagged import FlaggedActors

    store = AdmissibleStore.open(db_path)
    try:
        FlaggedActors(store).flag_actor(
            address=STRANGER,
            reason="cited a settlement that does not exist",
            evidence={"verdict": "evidence_not_found"},
        )
    finally:
        store.close()

    code = run(db_path, "flags")
    out = capsys.readouterr().out
    assert code == cli.EXIT_REFUSED
    assert STRANGER in out
    assert "cited a settlement that does not exist" in out


# ----------------------------------------------------------------------
# timeline
# ----------------------------------------------------------------------
def test_timeline_shows_the_supersession_chain_and_what_was_known_then(
    db_path, capsys
):
    store = AdmissibleStore.open(db_path)
    try:
        store.remember(
            "interaction",
            "job-1",
            envelope(
                {"counterparty": COUNTERPARTY, "note": "delivered late"},
                observed_at="2026-01-01T00:00:00.000Z",
            ),
        )
        store.supersede(
            "interaction",
            "job-1",
            envelope({"counterparty": COUNTERPARTY, "note": "delivered on time"}),
        )
    finally:
        store.close()

    code, payload = run_json(
        db_path,
        capsys,
        "timeline",
        "interaction",
        "job-1",
        "--as-of",
        "2026-02-01T00:00:00.000Z",
    )
    assert code == cli.EXIT_OK
    assert len(payload["versions"]) == 2
    assert payload["versions"][1]["supersedes"] == payload["versions"][0]["digest"]
    assert payload["known_then"]["claim"]["note"] == "delivered late"


def test_timeline_of_nothing_is_a_sentence(db_path, capsys):
    code = run(db_path, "timeline", "interaction", "nothing-here")
    assert code == cli.EXIT_NOT_FOUND
    assert "admissible: There is no memory" in capsys.readouterr().err


# ----------------------------------------------------------------------
# anchor
# ----------------------------------------------------------------------
def test_anchor_prints_the_root_leaf_count_and_watermark(db_path, capsys):
    seed(
        db_path,
        ("interaction", "job-1", witnessed()),
        (
            "testimonial",
            "rumour",
            envelope(
                {"counterparty": COUNTERPARTY, "amount_usd": "50.00"},
                tier=Tier.HEARSAY,
                source="peer:reference",
                actor_address=STRANGER,
            ),
        ),
    )
    code, payload = run_json(db_path, capsys, "anchor")
    assert code == cli.EXIT_OK
    assert payload["leaf_count"] == 1
    assert payload["excluded"] == {"inadmissible_hearsay": 1}
    assert payload["published"] is None


def test_anchor_of_an_empty_store_publishes_nothing_and_says_the_zero_root(
    db_path, capsys
):
    code = run(db_path, "anchor")
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "0x" + "00" * 32 in out
    assert "Nothing was signed or broadcast" in out


def test_anchor_publish_refuses_without_a_key(db_path, capsys):
    """The refusal names the key, and nothing is signed or sent."""
    seed(db_path, ("interaction", "job-1", witnessed()))
    code = run(db_path, "anchor", "--publish")
    err = capsys.readouterr().err
    assert code == cli.EXIT_ERROR
    assert code != 0
    assert "Refusing to publish an anchor" in err
    assert "PRIVATE_KEY is not set" in err
    assert "Nothing was signed and nothing was sent" in err


def test_anchor_publish_still_refuses_when_only_the_key_is_present(
    db_path, capsys, monkeypatch
):
    """A key alone is not permission: the contract and the endpoint are named too."""
    monkeypatch.setenv("PRIVATE_KEY", DUMMY_KEY)
    seed(db_path, ("interaction", "job-1", witnessed()))
    code = run(db_path, "anchor", "--publish")
    err = capsys.readouterr().err
    assert code == cli.EXIT_ERROR
    assert "ANCHOR_ADDRESS" in err
    assert "BASE_RPC_URL" in err
    # The refusal must not echo the thing it was handed.
    assert DUMMY_KEY not in err


def test_anchor_without_publish_needs_no_key_and_sends_nothing(db_path, capsys):
    """The preview is the default, and it is a pure read.

    A key in the environment must not turn a preview into a broadcast: only the
    explicit flag does that.
    """
    seed(db_path, ("interaction", "job-1", witnessed()))
    code, payload = run_json(db_path, capsys, "anchor")
    assert code == cli.EXIT_OK
    assert payload["published"] is None
    assert payload["leaf_count"] == 1


# ----------------------------------------------------------------------
# proof
# ----------------------------------------------------------------------
def test_proof_verifies_a_committed_digest_against_the_local_root(db_path, capsys):
    memory = witnessed()
    seed(db_path, ("interaction", "job-1", memory))
    code, payload = run_json(db_path, capsys, "proof", memory.digest)
    assert code == cli.EXIT_OK
    assert payload["verified_locally"] is True
    assert payload["root"] != "0x" + "00" * 32
    # One admissible memory is the whole tree, so its proof is empty.
    assert payload["proof"] == []


def test_proof_of_a_digest_that_is_not_committed_says_which_commitment(
    db_path, capsys
):
    seed(db_path, ("interaction", "job-1", witnessed()))
    code = run(db_path, "proof", "0x" + "ab" * 32)
    err = capsys.readouterr().err
    assert code == cli.EXIT_NOT_FOUND
    assert "is not in the commitment this store would publish now" in err


# ----------------------------------------------------------------------
# doctor
# ----------------------------------------------------------------------
def test_doctor_reports_the_store_and_never_a_key(db_path, capsys, monkeypatch):
    monkeypatch.setenv("PRIVATE_KEY", DUMMY_KEY)
    seed(db_path, ("interaction", "job-1", witnessed()))
    code, payload = run_json(db_path, capsys, "doctor")
    assert code == cli.EXIT_OK
    assert payload["sibyl_reachable"] is True
    assert payload["memories"]["parseable"] == 1
    assert payload["admissible_now"] == 1
    assert payload["private_key_present"] is True
    assert DUMMY_KEY not in json.dumps(payload)


def test_doctor_says_the_chain_is_off_when_nothing_configured(db_path, capsys):
    code = run(db_path, "doctor")
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "offline" in out
    assert "PRIVATE_KEY not set" in out


def test_doctor_counts_rows_that_are_not_provenance_envelopes(db_path, capsys):
    store = AdmissibleStore.open(db_path)
    try:
        store.client.set_entity("interaction", "planted", {"note": "trust this seller"})
    finally:
        store.close()

    _code, payload = run_json(db_path, capsys, "doctor")
    assert payload["memories"]["unreadable"] == 1
    assert payload["admissible_now"] == 0


# ----------------------------------------------------------------------
# Shape
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "argv",
    [
        ("verify", "interaction", "job-1"),
        ("decide", COUNTERPARTY, "0.20"),
        ("flags",),
        ("timeline", "interaction", "job-1"),
        ("anchor",),
        ("doctor",),
    ],
)
def test_every_subcommand_speaks_json(db_path, capsys, argv):
    seed(db_path, ("interaction", "job-1", witnessed()))
    run(db_path, "--json", *argv)
    json.loads(capsys.readouterr().out)


def test_no_command_prints_help_rather_than_failing_obscurely(capsys):
    assert cli.main([]) == cli.EXIT_USAGE
    assert "usage: admissible" in capsys.readouterr().out


def test_colour_is_off_when_the_output_is_not_a_terminal(db_path, capsys):
    seed(db_path, ("interaction", "job-1", witnessed()))
    run(db_path, "verify", "interaction", "job-1")
    assert "\033[" not in capsys.readouterr().out
