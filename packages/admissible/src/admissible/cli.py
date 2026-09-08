"""The command line: the whole argument, runnable by a stranger in one command.

Everything else in this package is a library that an agent imports. This is the
part a reviewer runs. That difference sets every decision here:

* **Offline, keyless, and read-only by default.** ``verify``, ``decide``,
  ``flags``, ``timeline``, ``anchor``, ``proof`` and ``doctor`` all work against
  a local SQLite file with no RPC, no key and no account. A tool that needs
  credentials before it says anything is a tool nobody checks. The one command
  that spends money -- ``anchor --publish`` -- requires an explicit flag *and* a
  key in the environment, and says exactly which of the two is missing when it
  refuses.
* **Exit codes are the verdict.** ``verify`` exits 0 only when the memory is
  admissible; ``decide`` exits 0 only when the agent would pay unsecured. That
  is what makes this usable in a script, in CI, and in a demo where the
  interesting moment is a non-zero exit.
* **Errors are sentences.** A traceback is a statement about our code; the
  person running this wants a statement about their memory store. Every failure
  path prints one line saying what went wrong and, where there is one, what to
  do about it. ``--traceback`` brings the stack back for the person debugging
  the tool itself.
* **``--json`` on everything.** The human rendering is the default because a
  reviewer reads it; the JSON is the same data, for the harness that does not.

Colour is used only when the stream is a terminal that wants it, so piping the
output into a file or a judge's log leaves no escape codes behind.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

from .anchor import Commitment, commit, leaf_of
from .consolidate import DOSSIER_CATEGORY, INTERACTION_CATEGORY
from .envelope import Envelope, utcnow
from .flagged import FlagRecord, FlaggedActors
from .policy import TrustPolicy
from .store import AdmissibleStore, MalformedMemory
from .timeline import Timeline
from .verdicts import Verdict
from .wiring import build_gate

#: The memory is admissible / the agent would pay unsecured / the answer is yes.
EXIT_OK = 0
#: The memory is inadmissible, or the decision is to refuse. A deliberate no.
EXIT_REFUSED = 1
#: argparse's own code for a misused command line. Listed so the others avoid it.
EXIT_USAGE = 2
#: The agent would proceed, but only against collateral. Neither yes nor no.
EXIT_CONDITIONAL = 3
#: There is nothing at that location to answer about.
EXIT_NOT_FOUND = 4
#: Something failed that is not a verdict: an unreadable store, a missing key.
EXIT_ERROR = 5

#: Where Sibyl Memory keeps its database unless told otherwise.
DEFAULT_DB = Path.home() / ".sibyl-memory" / "memory.db"

#: Categories swept when a command is asked about a counterparty rather than
#: about one named memory. Overridable with ``ADMISSIBLE_CATEGORIES``.
DEFAULT_CATEGORIES: tuple[str, ...] = (
    INTERACTION_CATEGORY,
    "testimonial",
    DOSSIER_CATEGORY,
)

#: A bounded read. Sibyl clamps its own limits; naming ours keeps "every memory
#: in the store" an honest description of a query with a ceiling.
MAX_SWEEP = 10_000

#: The one function of ``AdmissibilityAnchor.sol`` this CLI calls. Inlined
#: rather than shipped as an ABI file because a single write is easier to audit
#: as four lines here than as a JSON blob somebody has to open: what gets signed
#: is visible in the same file as the refusal that guards it.
ANCHOR_ABI = [
    {
        "type": "function",
        "name": "anchor",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "root", "type": "bytes32"},
            {"name": "asOf", "type": "uint64"},
            {"name": "leafCount", "type": "uint32"},
        ],
        "outputs": [{"name": "index", "type": "uint256"}],
    }
]


class CommandError(Exception):
    """A failure the user can do something about. Printed as one sentence."""

    def __init__(self, message: str, code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.code = code


# ----------------------------------------------------------------------
# Presentation
# ----------------------------------------------------------------------
class Style:
    """Colour, when the terminal wants it, and never otherwise.

    Honours ``NO_COLOR`` and a dumb ``TERM`` as well as the explicit flag: a
    reviewer piping this into a log file should get text, not escape codes.
    """

    CODES = {
        "bold": "1",
        "dim": "2",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "cyan": "36",
    }

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    @classmethod
    def resolve(cls, mode: str, stream: Any) -> "Style":
        if mode == "always":
            return cls(True)
        if mode == "never":
            return cls(False)
        if os.environ.get("NO_COLOR") is not None:
            return cls(False)
        if os.environ.get("TERM", "") == "dumb":
            return cls(False)
        return cls(bool(getattr(stream, "isatty", lambda: False)()))

    def __call__(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        codes = ";".join(self.CODES[n] for n in names if n in self.CODES)
        return f"\033[{codes}m{text}\033[0m" if codes else text


def _emit(payload: dict[str, Any]) -> None:
    """Print one JSON document. Sorted keys so diffs between runs are readable."""
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _short(value: str | None, size: int = 10) -> str:
    if not value:
        return "-"
    return value if len(value) <= size else value[:size]


def _money(value: float) -> str:
    return f"${value:,.2f}"


# ----------------------------------------------------------------------
# Wiring
# ----------------------------------------------------------------------
def _db_path(args: argparse.Namespace) -> Path:
    raw = args.db or os.environ.get("ADMISSIBLE_DB") or os.environ.get("SIBYL_MEMORY_DB")
    return Path(raw).expanduser() if raw else DEFAULT_DB


def _open_store(args: argparse.Namespace) -> AdmissibleStore:
    path = _db_path(args)
    tenant = os.environ.get("SIBYL_TENANT_ID")
    try:
        if tenant:
            return AdmissibleStore.open(path, tenant_id=tenant)
        return AdmissibleStore.open(path)
    except Exception as exc:  # noqa: BLE001 - a store that will not open is a sentence
        raise CommandError(
            f"Could not open the memory store at {path}: {exc}. "
            "Pass --db to point at a different file."
        ) from exc


def _chain(args: argparse.Namespace) -> tuple[Any | None, str]:
    """A Base reader if one was asked for, plus a sentence describing the choice.

    No RPC means no chain reader, which means ATTESTED memories verdict as
    ``chain_unreachable`` rather than as admitted. That is the correct answer
    offline: the gate refuses what it cannot re-derive, and a CLI that quietly
    assumed otherwise would be lying about the strongest tier it has.
    """
    url = args.rpc or os.environ.get("BASE_RPC_URL")
    if not url:
        return None, (
            "offline: no chain reader, so attested memories cannot be re-derived. "
            "Set BASE_RPC_URL or pass --rpc to verify them."
        )
    try:
        from .chain import BASE_MAINNET, BaseChain

        return BaseChain(rpc_url=url, config=BASE_MAINNET), f"reading Base mainnet at {url}"
    except Exception as exc:  # noqa: BLE001
        raise CommandError(
            f"Could not build a chain reader for {url}: {type(exc).__name__}: {exc}"
        ) from exc


def _gate_for(store: AdmissibleStore, args: argparse.Namespace) -> tuple[Any, str]:
    chain, note = _chain(args)
    self_address = args.self_address or os.environ.get("ADMISSIBLE_SELF_ADDRESS")
    gate, _history = build_gate(store, chain, self_address=self_address)
    return gate, note


def _categories() -> tuple[str, ...]:
    raw = os.environ.get("ADMISSIBLE_CATEGORIES") or ""
    chosen = tuple(c.strip() for c in raw.split(",") if c.strip())
    return chosen or DEFAULT_CATEGORIES


def _walk(
    store: AdmissibleStore, categories: Iterable[str | None]
) -> tuple[list[tuple[str, str, Envelope]], list[MalformedMemory]]:
    """Every stored row in these categories, split into readable and not.

    Unreadable rows are returned rather than dropped. A body nobody can parse is
    a fact about the store, and hiding it would make every count in this CLI
    look more complete than it is.
    """
    good: list[tuple[str, str, Envelope]] = []
    bad: list[MalformedMemory] = []
    for category in categories:
        for row in store.client.list_entities(category, limit=MAX_SWEEP):
            parsed = store.parse_body(row["category"], row["name"], row["body"])
            if isinstance(parsed, Envelope):
                good.append((row["category"], row["name"], parsed))
            else:
                bad.append(parsed)
    return good, bad


def _commitment(store: AdmissibleStore, gate: Any) -> tuple[Commitment, dict[str, int]]:
    """The anchor this store would publish now, and what it left out.

    Only admissible memories are committed. Anchoring the rest would commit to
    hearsay and forgeries alongside evidence and make the root mean nothing: an
    anchor is a claim about what the agent is willing to act on.
    """
    found, _ = _walk(store, (None,))
    pairs: list[tuple[str, str]] = []
    excluded: dict[str, int] = {}
    for _, _, envelope in found:
        verdict = gate.admit(envelope)
        if verdict.admits:
            pairs.append((envelope.digest, envelope.provenance.observed_at))
        else:
            excluded[verdict.code.value] = excluded.get(verdict.code.value, 0) + 1
    return commit(pairs), dict(sorted(excluded.items()))


# ----------------------------------------------------------------------
# verify
# ----------------------------------------------------------------------
def cmd_verify(args: argparse.Namespace, style: Style) -> int:
    """The verdict for one memory. Exit 0 only if it may move money."""
    store = _open_store(args)
    try:
        gate, chain_note = _gate_for(store, args)
        row = store.recall(args.category, args.name)
        if row is None:
            raise CommandError(
                f"There is no memory at {args.category}/{args.name} in "
                f"{_db_path(args)}.",
                EXIT_NOT_FOUND,
            )
        if isinstance(row, MalformedMemory):
            verdict = row.verdict
            envelope = None
        else:
            envelope = row
            verdict = gate.admit(row)

        if args.json:
            payload: dict[str, Any] = {
                "category": args.category,
                "name": args.name,
                "admissible": verdict.admits,
                "verdict": verdict.to_dict(),
                "chain": chain_note,
            }
            if envelope is not None:
                payload.update(
                    digest=envelope.digest,
                    tier=envelope.tier.value,
                    source=envelope.provenance.source,
                    actor_address=envelope.provenance.actor_address,
                    observed_at=envelope.provenance.observed_at,
                    evidence=envelope.provenance.evidence.to_dict(),
                    claim=envelope.claim,
                )
            else:
                payload["unparsed_body"] = row.body
            _emit(payload)
        else:
            _print_verdict(args.category, args.name, envelope, verdict, chain_note, style)
        return EXIT_OK if verdict.admits else EXIT_REFUSED
    finally:
        store.close()


def _print_verdict(
    category: str,
    name: str,
    envelope: Envelope | None,
    verdict: Verdict,
    chain_note: str,
    style: Style,
) -> None:
    stance = "ADMISSIBLE" if verdict.admits else "INADMISSIBLE"
    colour = "green" if verdict.admits else "red"
    print(style(f"{category}/{name}", "bold"))
    if envelope is not None:
        prov = envelope.provenance
        print(f"  digest    {envelope.digest}")
        print(
            f"  {envelope.tier.value:<9} from {prov.source}"
            + (f", asserted by {prov.actor_address}" if prov.actor_address else "")
        )
        print(f"  observed  {prov.observed_at}")
        evidence = prov.evidence.to_dict()
        if evidence:
            print(
                "  evidence  "
                + "  ".join(f"{k}={v}" for k, v in sorted(evidence.items()))
            )
    print(f"  {style(stance, colour, 'bold')}  ({verdict.code.value})")
    print(f"  {verdict.explain}")
    if verdict.fields:
        print(f"  decided by  {', '.join(verdict.fields)}")
    for key, value in sorted(verdict.detail.items()):
        print(f"    {key}: {value}")
    print(style(f"  chain     {chain_note}", "dim"))


# ----------------------------------------------------------------------
# decide
# ----------------------------------------------------------------------
def cmd_decide(args: argparse.Namespace, style: Style) -> int:
    """Recall everything about a counterparty, gate it, and act. With citations."""
    store = _open_store(args)
    try:
        gate, chain_note = _gate_for(store, args)
        flags = FlaggedActors(store)
        found, malformed = _walk(store, _categories())
        needle = args.counterparty.strip().casefold()
        about = [
            (category, name, envelope)
            for category, name, envelope in found
            if isinstance(envelope.claim.get("counterparty"), str)
            and envelope.claim["counterparty"].strip().casefold() == needle
        ]
        about.sort(key=lambda item: (item[2].provenance.observed_at, item[0], item[1]))

        judged = [(envelope, gate.admit(envelope)) for _, _, envelope in about]
        decision = TrustPolicy().decide(
            args.counterparty,
            args.amount,
            judged,
            flagged=flags.is_flagged(args.counterparty),
        )

        if args.json:
            payload = decision.to_dict()
            for view, (category, name, _) in zip(payload["considered"], about):
                view["category"] = category
                view["name"] = name
            payload["chain"] = chain_note
            payload["unreadable_rows"] = [
                {"category": row.category, "name": row.name, "reason": row.reason}
                for row in malformed
            ]
            _emit(payload)
        else:
            _print_decision(decision, about, malformed, chain_note, style)

        return {
            "pay": EXIT_OK,
            "escrow": EXIT_CONDITIONAL,
            "refuse": EXIT_REFUSED,
        }[decision.action]
    finally:
        store.close()


def _print_decision(
    decision: Any,
    about: Sequence[tuple[str, str, Envelope]],
    malformed: Sequence[MalformedMemory],
    chain_note: str,
    style: Style,
) -> None:
    colour = {"pay": "green", "escrow": "yellow", "refuse": "red"}[decision.action]
    print(
        style(decision.action.upper(), colour, "bold")
        + f"  {_money(decision.requested_usd)} to {decision.counterparty}"
    )
    print(f"  {decision.explain}")
    print(
        f"  credit {_money(decision.credit_usd)}   "
        f"unsecured {_money(decision.unsecured_usd)}   "
        f"collateral {_money(decision.collateral_usd)}"
    )
    if decision.blocked_by:
        print(style(f"  blocked by  {decision.blocked_by}", "red"))
    for warning in decision.warnings:
        print(style(f"  warning     {warning}", "yellow"))

    considered = decision.considered
    print(
        f"  considered  {len(considered)} memories, "
        f"{len(decision.admitted)} admissible, {len(decision.refused)} refused"
    )
    locations = {index: about[index][:2] for index in range(len(about))}
    for index, item in enumerate(considered):
        mark = style("+", "green") if item.verdict.admits else style("-", "red")
        category, name = locations.get(index, ("?", "?"))
        print(
            f"    {mark} {_short(item.digest)}  {item.envelope.tier.value:<9} "
            f"{item.verdict.code.value:<22} {_money(item.weight_usd):>9}  "
            f"{category}/{name}"
        )
    citations = decision.citations()
    print(
        "  citations   "
        + (", ".join(_short(d) for d in citations) if citations else "none")
    )
    if malformed:
        print(
            style(
                f"  unreadable  {len(malformed)} row(s) in the swept categories "
                "could not be parsed as provenance envelopes",
                "yellow",
            )
        )
    print(style(f"  chain       {chain_note}", "dim"))


# ----------------------------------------------------------------------
# flags
# ----------------------------------------------------------------------
def cmd_flags(args: argparse.Namespace, style: Style) -> int:
    """The FLAGGED tier as a table. Exit 1 when anybody is flagged."""
    store = _open_store(args)
    try:
        records = FlaggedActors(store).list_flags(include_revoked=args.all)
        if args.json:
            _emit(
                {
                    "count": len(records),
                    "include_revoked": args.all,
                    "flags": [_flag_dict(record) for record in records],
                }
            )
        elif not records:
            print("No flagged actors. Nothing in this store is refused on sight.")
        else:
            print(style(f"{len(records)} flagged actor(s)", "bold"))
            header = f"  {'ACTOR':<44} {'HANDLE':<20} {'FLAGGED':<26} REASON"
            print(style(header, "dim"))
            for record in records:
                line = (
                    f"  {(record.actor_address or '-'):<44} "
                    f"{(record.actor_handle or '-'):<20} "
                    f"{record.flagged_at:<26} {record.reason}"
                )
                print(line if record.is_active else style(line + "  (revoked)", "dim"))
        return EXIT_REFUSED if any(r.is_active for r in records) else EXIT_OK
    finally:
        store.close()


def _flag_dict(record: FlagRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "actor_address": record.actor_address,
        "actor_handle": record.actor_handle,
        "flagged_at": record.flagged_at,
        "reason": record.reason,
        "evidence": record.evidence,
        "active": record.is_active,
        "revoked_at": record.revoked_at,
        "revoked_reason": record.revoked_reason,
    }


# ----------------------------------------------------------------------
# timeline
# ----------------------------------------------------------------------
def cmd_timeline(args: argparse.Namespace, style: Style) -> int:
    """The supersession history of one memory, and what was known at a moment."""
    store = _open_store(args)
    try:
        timeline = Timeline(store)
        versions = timeline.versions(args.category, args.name)
        lost = timeline.unreconstructible(args.category, args.name)
        if not versions and not lost:
            raise CommandError(
                f"There is no memory at {args.category}/{args.name} in "
                f"{_db_path(args)}, and nothing in the journal about one.",
                EXIT_NOT_FOUND,
            )

        gate, chain_note = _gate_for(store, args)
        held = timeline.as_of(args.category, args.name, args.as_of) if args.as_of else None
        held_verdict = gate.admit(held) if held is not None else None

        if args.json:
            _emit(
                {
                    "category": args.category,
                    "name": args.name,
                    "versions": [
                        {
                            "digest": v.envelope.digest,
                            "tier": v.envelope.tier.value,
                            "source": v.envelope.provenance.source,
                            "observed_at": v.envelope.provenance.observed_at,
                            "recorded_at": v.recorded_at,
                            "origin": v.origin,
                            "supersedes": v.envelope.provenance.supersedes,
                            "claim": v.envelope.claim,
                        }
                        for v in versions
                    ],
                    "unreconstructible": lost,
                    "as_of": args.as_of,
                    "known_then": None
                    if held is None
                    else {
                        "digest": held.digest,
                        "tier": held.tier.value,
                        "claim": held.claim,
                        "verdict": held_verdict.to_dict() if held_verdict else None,
                    },
                    "chain": chain_note,
                }
            )
            return EXIT_OK

        print(style(f"{args.category}/{args.name}", "bold"))
        print(
            style(
                f"  {len(versions)} recoverable version(s), oldest first", "dim"
            )
        )
        for version in versions:
            envelope = version.envelope
            print(
                f"  {_short(envelope.digest)}  {envelope.tier.value:<9} "
                f"{envelope.provenance.observed_at}  recorded {version.recorded_at}  "
                f"[{version.origin}]"
            )
            if envelope.provenance.supersedes:
                print(
                    style(
                        f"      supersedes {_short(envelope.provenance.supersedes)}",
                        "dim",
                    )
                )
        if lost:
            print(
                style(
                    f"  {len(lost)} version(s) existed and cannot be reconstructed: "
                    + ", ".join(_short(rec.get('digest')) for rec in lost),
                    "yellow",
                )
            )
            print(
                style(
                    "  A bare overwrite journals the write but not the body, so any "
                    "replay across that window is incomplete.",
                    "dim",
                )
            )
        if args.as_of:
            print(style(f"  as of {args.as_of}", "bold"))
            if held is None:
                print(
                    "    Nothing this store can show was known then -- either the "
                    "memory did not exist yet, or the version held then was "
                    "overwritten without being archived."
                )
            else:
                stance = "ADMISSIBLE" if held_verdict.admits else "INADMISSIBLE"
                colour = "green" if held_verdict.admits else "red"
                print(
                    f"    {_short(held.digest)}  {held.tier.value}  "
                    + style(stance, colour)
                    + f" ({held_verdict.code.value})"
                )
                print(f"    {json.dumps(held.claim, sort_keys=True, default=str)}")
        return EXIT_OK
    finally:
        store.close()


# ----------------------------------------------------------------------
# anchor
# ----------------------------------------------------------------------
def cmd_anchor(args: argparse.Namespace, style: Style) -> int:
    """Print the anchor this store would publish, and publish it only if asked."""
    store = _open_store(args)
    try:
        gate, chain_note = _gate_for(store, args)
        commitment, excluded = _commitment(store, gate)

        published: dict[str, Any] | None = None
        if args.publish:
            published = _publish_anchor(commitment, args)

        if args.json:
            _emit(
                {
                    "root": commitment.root_hex,
                    "leaf_count": commitment.leaf_count,
                    "as_of": commitment.as_of,
                    "excluded": excluded,
                    "chain": chain_note,
                    "published": published,
                }
            )
        else:
            print(style("anchor preview", "bold"))
            print(f"  root        {commitment.root_hex}")
            print(f"  leaves      {commitment.leaf_count}")
            print(f"  as of       {commitment.as_of}")
            if excluded:
                print(
                    "  excluded    "
                    + ", ".join(f"{code} {count}" for code, count in excluded.items())
                )
            if commitment.leaf_count == 0:
                print(
                    style(
                        "  Nothing in this store is admissible right now. The zero "
                        "root is a real position and publishing it is honest.",
                        "dim",
                    )
                )
            if published:
                print(style(f"  published   {published['tx_hash']}", "green"))
                print(f"  contract    {published['contract']}")
                print(f"  from        {published['from']}")
            else:
                print(
                    style(
                        "  Nothing was signed or broadcast. Add --publish with "
                        "PRIVATE_KEY set to send this anchor.",
                        "dim",
                    )
                )
        return EXIT_OK
    finally:
        store.close()


def _publish_anchor(commitment: Commitment, args: argparse.Namespace) -> dict[str, Any]:
    """Sign and broadcast one anchor. Refuses loudly rather than half-trying.

    Three things have to be present and every one of them is checked before
    anything is built, so a missing key is a sentence rather than an exception
    from inside a signing library. The key is read from the environment and is
    never printed, logged, or written anywhere -- ``doctor`` reports only whether
    it exists.
    """
    missing: list[str] = []
    key = os.environ.get("PRIVATE_KEY")
    if not key:
        missing.append(
            "PRIVATE_KEY is not set in the environment (this is the only place "
            "this tool will read a key from)"
        )
    address = args.anchor_address or os.environ.get("ANCHOR_ADDRESS")
    if not address:
        missing.append(
            "the AdmissibilityAnchor address is unknown; pass --anchor-address "
            "or set ANCHOR_ADDRESS"
        )
    rpc = args.rpc or os.environ.get("BASE_RPC_URL")
    if not rpc:
        missing.append("no RPC endpoint; pass --rpc or set BASE_RPC_URL")

    if missing:
        raise CommandError(
            "Refusing to publish an anchor: " + "; ".join(missing) + ". "
            "Nothing was signed and nothing was sent."
        )

    try:
        from eth_account import Account
        from web3 import Web3
    except ImportError as exc:  # pragma: no cover - web3 is a declared dependency
        raise CommandError(
            f"Publishing needs web3 and eth-account, which are not importable: {exc}"
        ) from exc

    try:
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
        account = Account.from_key(key)
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(address), abi=ANCHOR_ABI
        )
        call = contract.functions.anchor(
            bytes.fromhex(commitment.root_hex[2:]),
            commitment.as_of_unix,
            commitment.leaf_count,
        )
        tx = call.build_transaction(
            {
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address),
                "chainId": w3.eth.chain_id,
            }
        )
        # Estimating first doubles as a dry run: a call that would revert -- an
        # `asOf` older than the last anchor, most likely -- fails here, before
        # anything is signed and before any fee is spent.
        tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    except Exception as exc:  # noqa: BLE001 - a failed broadcast is a sentence
        raise CommandError(
            f"The anchor transaction did not go through: {type(exc).__name__}: {exc}"
        ) from exc

    return {
        "tx_hash": receipt["transactionHash"].hex()
        if hasattr(receipt["transactionHash"], "hex")
        else str(receipt["transactionHash"]),
        "block": receipt["blockNumber"],
        "status": receipt["status"],
        "contract": address,
        "from": account.address,
        "root": commitment.root_hex,
        "leaf_count": commitment.leaf_count,
        "as_of": commitment.as_of,
    }


# ----------------------------------------------------------------------
# proof
# ----------------------------------------------------------------------
def cmd_proof(args: argparse.Namespace, style: Style) -> int:
    """The Merkle proof for one digest against the latest local commitment."""
    store = _open_store(args)
    try:
        gate, _ = _gate_for(store, args)
        commitment, _excluded = _commitment(store, gate)
        digest = args.digest if args.digest.startswith("0x") else "0x" + args.digest
        try:
            path = commitment.tree.proof_hex(digest)
        except (KeyError, ValueError) as exc:
            raise CommandError(
                f"{digest} is not in the commitment this store would publish now "
                f"({commitment.leaf_count} admissible memories). Either the memory "
                f"is not admissible, or that is not one of its digests. ({exc})",
                EXIT_NOT_FOUND,
            ) from exc

        verified = commitment.tree.verify(
            digest, [bytes.fromhex(node[2:]) for node in path]
        )
        if args.json:
            _emit(
                {
                    "digest": digest,
                    "leaf": "0x" + leaf_of(digest).hex(),
                    "root": commitment.root_hex,
                    "leaf_count": commitment.leaf_count,
                    "as_of": commitment.as_of,
                    "proof": path,
                    "verified_locally": verified,
                }
            )
        else:
            print(style("merkle proof", "bold"))
            print(f"  digest      {digest}")
            print(f"  leaf        0x{leaf_of(digest).hex()}")
            print(f"  root        {commitment.root_hex}")
            print(f"  leaves      {commitment.leaf_count}")
            print(f"  as of       {commitment.as_of}")
            print(f"  proof       {len(path)} sibling(s)")
            for node in path:
                print(f"    {node}")
            print(
                "  "
                + style(
                    "verified against the local root"
                    if verified
                    else "DOES NOT verify against the local root",
                    "green" if verified else "red",
                )
            )
            print(
                style(
                    "  Check it onchain with AdmissibilityAnchor.verifyLatest(agent, "
                    "leaf, proof).",
                    "dim",
                )
            )
        return EXIT_OK if verified else EXIT_REFUSED
    finally:
        store.close()


# ----------------------------------------------------------------------
# doctor
# ----------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace, style: Style) -> int:
    """Is this environment able to answer honestly? Reports, never guesses.

    Presence is reported for every credential; a value is reported for none of
    them. A diagnostic command that prints a key is a diagnostic command nobody
    can run in a screen share.
    """
    report: dict[str, Any] = {}
    path = _db_path(args)
    report["database"] = {"path": str(path), "exists": path.exists()}
    if path.exists():
        report["database"]["size_bytes"] = path.stat().st_size

    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            report["sibyl_memory_client"] = version("sibyl-memory-client")
        except PackageNotFoundError:
            report["sibyl_memory_client"] = None
    except Exception:  # noqa: BLE001 - metadata is a nicety, not a requirement
        report["sibyl_memory_client"] = None

    store: AdmissibleStore | None = None
    try:
        store = _open_store(args)
        report["sibyl_reachable"] = True
        report["tenant_id"] = store.tenant_id
        good, bad = _walk(store, (None,))
        report["memories"] = {
            "total": len(good) + len(bad),
            "parseable": len(good),
            "unreadable": len(bad),
        }
        gate, chain_note = _gate_for(store, args)
        report["chain"] = chain_note
        admitted = sum(1 for _, _, env in good if gate.admit(env).admits)
        report["admissible_now"] = admitted
        report["flagged_actors"] = len(FlaggedActors(store).list_flags())
        report["journal_events"] = len(store.journal(limit=MAX_SWEEP))
    except CommandError as exc:
        report["sibyl_reachable"] = False
        report["error"] = str(exc)
    finally:
        if store is not None:
            store.close()

    # Presence only. Never the value, not even truncated.
    report["private_key_present"] = bool(os.environ.get("PRIVATE_KEY"))
    report["anchor_address"] = args.anchor_address or os.environ.get("ANCHOR_ADDRESS")
    report["self_address"] = args.self_address or os.environ.get("ADMISSIBLE_SELF_ADDRESS")
    report["categories"] = list(_categories())
    report["checked_at"] = utcnow()

    if args.json:
        _emit(report)
        return EXIT_OK if report.get("sibyl_reachable") else EXIT_ERROR

    ok = bool(report.get("sibyl_reachable"))
    print(style("admissible doctor", "bold"))
    print(
        "  sibyl memory   "
        + (style("reachable", "green") if ok else style("NOT reachable", "red"))
        + f"  (client {report.get('sibyl_memory_client') or 'not installed'})"
    )
    db = report["database"]
    print(
        f"  database       {db['path']}  "
        + (f"{db.get('size_bytes', 0):,} bytes" if db["exists"] else "does not exist yet")
    )
    if ok:
        memories = report["memories"]
        print(f"  tenant         {report['tenant_id']}")
        print(
            f"  memories       {memories['total']} total, "
            f"{memories['parseable']} parseable, {memories['unreadable']} unreadable"
        )
        print(f"  admissible     {report['admissible_now']} right now")
        print(f"  flagged        {report['flagged_actors']} actor(s)")
        print(f"  journal        {report['journal_events']} event(s)")
        print(f"  chain          {report['chain']}")
    else:
        print(style(f"  error          {report.get('error')}", "red"))
    print(
        "  signing key    "
        + (
            style("PRIVATE_KEY is set (value never read here or printed)", "yellow")
            if report["private_key_present"]
            else "PRIVATE_KEY not set; anchor --publish will refuse"
        )
    )
    print(f"  anchor         {report['anchor_address'] or 'ANCHOR_ADDRESS not set'}")
    print(f"  self address   {report['self_address'] or 'not set (see --self-address)'}")
    return EXIT_OK if ok else EXIT_ERROR


# ----------------------------------------------------------------------
# Wiring the parser
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="admissible",
        description=(
            "Provenance-gated memory for agents that move money. Every command "
            "reads a local Sibyl Memory database and works offline with no keys."
        ),
        epilog=(
            "Exit codes: 0 admissible / would pay, 1 inadmissible / refused, "
            "2 bad command line, 3 escrow (conditional), 4 nothing there, "
            "5 something failed that is not a verdict."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--db",
        metavar="PATH",
        help="memory database (default: $ADMISSIBLE_DB, $SIBYL_MEMORY_DB, "
        "or ~/.sibyl-memory/memory.db)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colour output (default: auto, which means only on a terminal)",
    )
    parser.add_argument(
        "--rpc",
        metavar="URL",
        help="Base RPC endpoint; without one, attested memories cannot be "
        "re-derived and verdict as chain_unreachable (default: $BASE_RPC_URL)",
    )
    parser.add_argument(
        "--self-address",
        metavar="ADDRESS",
        help="this agent's wallet, so a settlement has to involve us rather than "
        "merely exist (default: $ADMISSIBLE_SELF_ADDRESS)",
    )
    parser.add_argument(
        "--anchor-address",
        metavar="ADDRESS",
        help="deployed AdmissibilityAnchor contract (default: $ANCHOR_ADDRESS)",
    )
    parser.add_argument(
        "--traceback",
        action="store_true",
        help="show the stack on failure, for debugging this tool rather than a store",
    )

    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    verify = subs.add_parser(
        "verify", help="the verdict for one memory (exit 0 if it may move money)"
    )
    verify.add_argument("category")
    verify.add_argument("name")
    verify.set_defaults(func=cmd_verify)

    decide = subs.add_parser(
        "decide", help="what the agent would do about a payment request, with citations"
    )
    decide.add_argument("counterparty", help="address or handle")
    decide.add_argument("amount", type=float, help="requested amount in USD")
    decide.set_defaults(func=cmd_decide)

    flags = subs.add_parser("flags", help="the FLAGGED tier")
    flags.add_argument(
        "--all", action="store_true", help="include revoked flags, which are never deleted"
    )
    flags.set_defaults(func=cmd_flags)

    timeline = subs.add_parser(
        "timeline", help="the supersession history of one memory"
    )
    timeline.add_argument("category")
    timeline.add_argument("name")
    timeline.add_argument(
        "--as-of",
        metavar="TS",
        help="ISO-8601 instant: show the version the agent held then",
    )
    timeline.set_defaults(func=cmd_timeline)

    anchor = subs.add_parser(
        "anchor", help="the root, leaf count and watermark that would be published"
    )
    anchor.add_argument(
        "--publish",
        action="store_true",
        help="sign and broadcast the anchor; requires PRIVATE_KEY, an anchor "
        "address and an RPC, and refuses loudly without them",
    )
    anchor.set_defaults(func=cmd_anchor)

    proof = subs.add_parser(
        "proof", help="the Merkle proof for a digest against the latest local commitment"
    )
    proof.add_argument("digest", help="0x-prefixed memory digest")
    proof.set_defaults(func=cmd_proof)

    doctor = subs.add_parser("doctor", help="environment check: store, chain, keys")
    doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one command. Returns the exit code rather than calling ``sys.exit``.

    Returning it keeps every command testable in-process: a test asserts on the
    integer, and nothing has to catch ``SystemExit`` to find out what happened.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE

    style = Style.resolve(args.color, sys.stdout)
    try:
        return args.func(args, style)
    except CommandError as exc:
        print(f"admissible: {exc}", file=sys.stderr)
        if args.traceback:
            raise
        return exc.code
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("admissible: interrupted before anything was written.", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - a traceback is not a user-facing answer
        if args.traceback:
            raise
        print(
            f"admissible: {type(exc).__name__}: {exc} "
            "(run again with --traceback for the stack)",
            file=sys.stderr,
        )
        return EXIT_ERROR


def run() -> None:
    """Console-script shim: turn the returned code into a process exit code."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover - module execution
    run()
