"""MCP server exposing Sibyl Memory with the admission gate in front of it.

Sibyl Labs ships an MCP server over the same database: ``memory_remember``,
``memory_recall``, ``memory_search``, and five more. It is a good server and it
answers the question it was asked -- what is stored. This one answers a
different question: what is *allowed to matter*. Same file, same tenant, same
rows; every read runs through :class:`~admissible.gate.AdmissionGate` first, and
what comes back is a claim bolted to a verdict.

THE DESIGN RULE
---------------
**An MCP tool result is untrusted input to whatever model called it.**

A tool result arrives in the caller's context indistinguishable from anything
else it is reading. The model has no way to tell a memory backed by a settled
onchain payment from a memory an attacker wrote into the same SQLite file a
minute ago -- and a memory store that anything can write to is precisely how a
payment gets steered. So the rule is not "be careful what you return"; it is
that the server is built so the careless thing cannot be returned.

Every tool that surfaces remembered content returns the verdict alongside it,
and no tool returns a bare claim. That is enforced mechanically in
:mod:`admissible_mcp.views`: :func:`~admissible_mcp.views.memory_view` is the
only function that renders a claim and it takes the verdict as a required
argument, and :func:`~admissible_mcp.views.guard` re-checks every response on
the way out and raises if a claim ever appears without one. A calling model
should find it *impossible* to get "counterparty X delivered twelve times" out
of this server without also getting "HEARSAY, inadmissible, nothing
corroborates it" in the same object.

The rest follows from that. ``admissible_remember`` refuses to write ATTESTED
without an evidence location, because a tier is a label and a label is not
evidence -- writing one would let a model launder its own assertion into
something the gate later admits. ``admissible_decide`` returns refused memories
with their reasons rather than hiding them, because a decision that cannot show
what it rejected is indistinguishable from one that never looked. And nothing
here holds a signer: the server reads chains, it does not write to them, so
there is no sequence of tool calls that spends anything.

WHAT IT DOES NOT DO
-------------------
It does not search. Ranking is Sibyl's job and it is good at it; adding a
lexical search here would mean surfacing rows on relevance rather than on
provenance, which is the habit this package exists to break. Run Sibyl's server
alongside this one if you want both.
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, NoReturn

from admissible.anchor import commit
from admissible.consolidate import consolidate, summarize
from admissible.envelope import Envelope, Evidence, Provenance, Tier
from admissible.policy import TrustPolicy
from admissible.store import MalformedMemory
from admissible.timeline import Timeline
from admissible.verdicts import Verdict

from .session import MAX_SWEEP, Session, session
from .views import UnverdictedClaim, fence, guard, malformed_view, memory_view, scrub

try:  # mcp 2.x renamed FastMCP to MCPServer and moved the module.
    from mcp.server.mcpserver import MCPServer as ToolServer
    from mcp.server.mcpserver.exceptions import ToolError
except ModuleNotFoundError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as ToolServer
    from mcp.server.fastmcp.exceptions import ToolError

SERVER_NAME = "admissible"

#: The tiers a caller may write, spelled out in every refusal so a model that
#: got it wrong is told the alternatives rather than left guessing.
TIER_NAMES = tuple(t.value for t in Tier)


# ----------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------
def _refuse(code: str, message: str, **extra: Any) -> NoReturn:
    """Fail a tool call at the protocol level, with a reason a model can act on.

    Raising :class:`ToolError` rather than returning ``{"ok": False}`` is the
    difference between a caller that sees ``isError`` and one that has to parse
    a success envelope to discover the call failed. The payload is JSON so both
    a model and a program can read it.
    """
    raise ToolError(json.dumps({"ok": False, "code": code, "message": message, **extra},
                               ensure_ascii=False, default=str))


def _sess() -> Session:
    return session()


# ----------------------------------------------------------------------
# Write
# ----------------------------------------------------------------------
def admissible_remember(
    category: str,
    name: str,
    claim: dict[str, Any],
    tier: str,
    source: str,
    actor_address: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store a memory WITH ITS PROVENANCE, then report what the gate makes of it.

    A memory here is a claim plus the story of how we came to hold it. The story
    is not decoration: it decides whether the claim may ever justify moving
    money, so it is required at write time rather than reconstructed later.

    Tiers, weakest first:
      HEARSAY    someone asserted it. Nothing backs it. It may inform a
                 conversation; it may never move money on its own.
      WITNESSED  our own agent saw it first-hand. Admissible with no chain call,
                 and capped in how far it can extend credit.
      ATTESTED   bound to onchain state anyone can re-derive -- a settled
                 payment, or an ERC-8004 feedback record whose committed digest
                 matches this claim.

    ATTESTED REQUIRES AN EVIDENCE LOCATION AND THIS TOOL REFUSES WITHOUT ONE.
    Writing the word "ATTESTED" into a field costs nothing, so an attested claim
    with nowhere to check is hearsay wearing a better hat. Pass either
    ``evidence.tx_hash`` (with ``chain_id``) for a settlement, or
    ``evidence.registry`` + ``agent_id`` + ``feedback_index`` for feedback. If
    you do not have one, write the memory as HEARSAY: an honest weak memory is
    worth more than a strong-looking one that fails at the gate.

    Args:
        category: Sibyl entity category, e.g. "interaction", "testimonial".
        name: Unique within the category, e.g. "acme-job-17".
        claim: The claim itself. For a payment memory include ``counterparty``
            and ``amount_usd`` -- the gate compares both against the chain, and
            a claim missing them cannot be re-derived.
        tier: One of HEARSAY, WITNESSED, ATTESTED.
        source: How it reached us: "agent:self", "peer:reference",
            "x402:settlement", "tool:fetch", "user". WITNESSED is only granted
            to this agent's own first-party source.
        actor_address: Who asserted it. This is the join key into the FLAGGED
            tier, so supply it whenever you have it -- an unattributed claim
            cannot be contaminated by its author being caught later.
        evidence: Where to look onchain: ``{chain_id, tx_hash, kind}`` or
            ``{chain_id, registry, agent_id, feedback_index, kind}``.

    Returns the stored memory rendered with the verdict the gate gives it
    immediately after the write, so a caller learns straight away that the
    memory it just wrote is inadmissible rather than discovering it at payment
    time.
    """
    if not isinstance(claim, dict):
        _refuse(
            "VALIDATION_ERROR",
            "claim must be a JSON object; a bare string has no fields for a "
            "verifier to check against the chain.",
        )
    try:
        parsed_tier = Tier(tier)
    except ValueError:
        _refuse(
            "VALIDATION_ERROR",
            f"unknown tier {tier!r}; use one of {', '.join(TIER_NAMES)}.",
            valid_tiers=list(TIER_NAMES),
        )
    if not source or not source.strip():
        _refuse(
            "VALIDATION_ERROR",
            "source is required: a memory whose origin nobody recorded cannot be "
            "weighed, contaminated, or defended later.",
        )

    try:
        parsed_evidence = Evidence.from_dict(evidence)
    except ValueError as exc:
        _refuse("VALIDATION_ERROR", f"evidence is not a well-formed location: {exc}")

    if parsed_tier is Tier.ATTESTED and parsed_evidence.is_empty:
        _refuse(
            "UNEVIDENCED_ATTESTATION",
            "Refusing to write an ATTESTED memory with no evidence location. "
            "ATTESTED means somebody other than the author can re-derive this "
            "claim, and nothing here says where to look. Supply "
            "evidence.tx_hash (a settled payment) or evidence.registry with "
            "agent_id and feedback_index (an ERC-8004 record) -- or write it as "
            "HEARSAY, which is what an unbacked assertion is.",
            recovery="add an evidence location, or set tier to HEARSAY",
            valid_tiers=list(TIER_NAMES),
        )

    sess = _sess()
    envelope = Envelope(
        claim=claim,
        provenance=Provenance(
            tier=parsed_tier,
            source=source,
            actor_address=actor_address,
            evidence=parsed_evidence,
        ),
    )
    try:
        row = sess.store.remember(category, name, envelope)
    except Exception as exc:  # noqa: BLE001 - storage errors are results, not crashes
        _refuse("STORAGE_ERROR", f"{type(exc).__name__}: {exc}")
    sess.invalidate()

    verdict = sess.gate.admit(envelope)
    return fence(
        {
            "ok": True,
            "written": memory_view(envelope, verdict, category=category, name=name),
            "journal_event_id": row.get("journal_event_id"),
            "note": (
                "Written and journalled. The verdict above is what this memory "
                "would contribute to a decision right now."
            ),
        }
    )


# ----------------------------------------------------------------------
# Read
# ----------------------------------------------------------------------
def admissible_recall(category: str, name: str) -> dict[str, Any]:
    """Read one memory, and never the claim alone.

    The result carries the claim, its provenance, and the gate's verdict on it
    in the same object. Read the verdict first: ``admissible: false`` means the
    claim may inform what you say and may not justify paying anybody, extending
    credit, or describing the counterparty as trustworthy.

    A row that is not a provenance envelope comes back as an explicit MALFORMED
    verdict with the raw body under ``unparsed_body`` -- an unreadable memory is
    a fact about the store, and on an attack it is often the most interesting
    one.
    """
    sess = _sess()
    row = sess.store.recall(category, name)
    if row is None:
        _refuse(
            "NOT_FOUND",
            f"no memory at {category}/{name} for this tenant.",
            category=category,
            name=name,
        )
    if isinstance(row, MalformedMemory):
        return fence({"ok": True, "memory": malformed_view(row)})
    verdict = sess.gate.admit(row)
    return fence(
        {"ok": True, "memory": memory_view(row, verdict, category=category, name=name)}
    )


def admissible_verify(category: str, name: str) -> dict[str, Any]:
    """Run the admission gate over one stored memory and return the full verdict.

    The verdict names three things and all three matter: the ``code``, the
    envelope ``fields`` that decided it, and an ``explain`` sentence written for
    a human reading it later without the source in front of them.

    Codes you will actually see, and what each means for money:
      admissible             re-derived from evidence; may justify a payment.
      inadmissible_hearsay   nothing corroborates it. Informs, never pays.
      evidence_not_found     it cites evidence that is not there. Forgery-shaped.
      digest_mismatch        the claim was edited after it was sealed.
      counterparty_mismatch  a real transaction, involving somebody else.
      amount_mismatch        a real transaction, for a different amount.
      superseded             a later memory replaced it.
      expired               true history, not current fact.
      flagged_source        its author is in the FLAGGED tier.
      backdated             injected now, dressed up as old.
      chain_unreachable     the chain could not be read. Unknown is not yes.
    """
    sess = _sess()
    row = sess.store.recall(category, name)
    if row is None:
        _refuse(
            "NOT_FOUND",
            f"no memory at {category}/{name} for this tenant.",
            category=category,
            name=name,
        )
    if isinstance(row, MalformedMemory):
        view = malformed_view(row)
        return fence({"ok": True, "verdict": view["verdict"], "memory": view})
    verdict = sess.gate.admit(row)
    return fence(
        {
            "ok": True,
            "verdict": verdict.to_dict(),
            "chain": sess.chain_status,
            "memory": memory_view(row, verdict, category=category, name=name),
        }
    )


def admissible_verify_claim(body: dict[str, Any]) -> dict[str, Any]:
    """Judge a provenance envelope that is not stored anywhere. Writes nothing.

    Use it to check a memory somebody just handed you -- a testimonial from a
    peer, a claim pasted into a conversation -- before deciding whether it is
    worth writing down. ``body`` is a full envelope:
    ``{"claim": {...}, "provenance": {"tier": ..., "source": ..., "evidence": {...}}}``.

    The gate never raises here. A body that is not an envelope at all comes back
    as MALFORMED, which is a verdict rather than an error, because on this path
    unparseable input is the expected case rather than the exceptional one.
    """
    if not isinstance(body, dict):
        _refuse(
            "VALIDATION_ERROR",
            "body must be a provenance envelope object with 'claim' and "
            "'provenance' keys.",
        )
    sess = _sess()
    verdict = sess.gate.admit(body)
    payload: dict[str, Any] = {
        "ok": True,
        "verdict": verdict.to_dict(),
        "chain": sess.chain_status,
        "stored": False,
    }
    try:
        envelope = Envelope.from_body(body)
    except Exception:  # noqa: BLE001 - the verdict already says what went wrong
        payload["unparsed_body"] = scrub(body)
        return fence(payload)
    payload["memory"] = memory_view(envelope, verdict)
    return fence(payload)


def admissible_decide(counterparty: str, requested_usd: float) -> dict[str, Any]:
    """Recall everything about a counterparty, gate all of it, and decide.

    This is the tool that matters. It is the whole product in one call: recall,
    admission, and a deterministic policy that turns re-derivable history into
    one of three actions.

      pay     admissible history covers the request. Release it unsecured.
      escrow  some credit, not enough. Release part, hold collateral for the
              rest until the work lands.
      refuse  nothing admissible justifies it -- or something in the pile was
              forged, or the counterparty is FLAGGED. Forgery is never escrowed:
              collateral protects against failure, not against fraud.

    No model runs inside the decision. The same admitted set always produces the
    same action, which is what makes it auditable a week later and replayable
    from a point-in-time snapshot.

    Every memory that was looked at comes back in ``considered`` -- admitted and
    refused alike, each with its verdict and the dollars of credit it
    contributed. The refused ones carry zero weight and are shown anyway: they
    are the visible evidence that something tried to move this decision and
    failed. ``citations`` lists the digests that actually moved it.

    Args:
        counterparty: Address or handle, matched against ``claim.counterparty``.
        requested_usd: What they are asking for, in dollars.
    """
    try:
        amount = float(requested_usd)
    except (TypeError, ValueError):
        _refuse("VALIDATION_ERROR", f"requested_usd is not an amount: {requested_usd!r}")
    if amount < 0 or amount != amount or amount in (float("inf"), float("-inf")):
        _refuse("VALIDATION_ERROR", "requested_usd must be a finite, non-negative amount.")

    sess = _sess()
    found = _memories_about(sess, counterparty)
    judged: list[tuple[Envelope, Verdict]] = [
        (env, sess.gate.admit(env)) for _, _, env in found
    ]
    flagged = sess.flags.is_flagged(counterparty)
    decision = TrustPolicy().decide(counterparty, amount, judged, flagged=flagged)

    payload = decision.to_dict()
    payload["considered"] = [scrub(item) for item in payload["considered"]]
    for view, (category, name, _) in zip(payload["considered"], found):
        view["category"] = category
        view["name"] = name
    return fence(
        {
            "ok": True,
            "headline": (
                f"{decision.action.upper()} ${amount:.2f} to {counterparty}: "
                f"{decision.explain}"
            ),
            "decision": payload,
            "chain": sess.chain_status,
            "searched_categories": list(sess.settings.categories),
            "malformed_rows": [malformed_view(row) for row in _malformed_rows(sess)],
        }
    )


def admissible_dossier(counterparty: str) -> dict[str, Any]:
    """Fold every memory about a counterparty into one record, plus its summary.

    Arithmetic, not summarisation: counts, sums, extremes. A model-written
    summary would be a new claim with no provenance of its own, generated from
    text that may itself have been planted -- exactly what the rest of this
    server refuses to admit. Every number here can be recomputed from the same
    database by anyone holding it.

    The dossier's tier is the WEAKEST tier among its inputs, so a fold that
    mixes an attested settlement with a stranger's assertion is not attested.
    ``attested_totals`` inside the claim carries the subtotal that is.

    Reads only. The dossier is computed for this answer and not written back,
    because a read tool that quietly writes changes what the next read sees.
    """
    sess = _sess()
    dossier = consolidate(sess.store, counterparty, write=False)
    verdict = sess.gate.admit(dossier)
    return fence(
        {
            "ok": True,
            "summary": summarize(dossier),
            "dossier": memory_view(dossier, verdict, name=counterparty),
            "note": (
                "Computed for this call and not stored. The tier is the weakest "
                "tier folded in; attested_totals is the part that is backed."
            ),
        }
    )


def admissible_as_of(category: str, name: str, when: str) -> dict[str, Any]:
    """What did the agent know about this memory at that moment?

    Transaction-time replay. Judging a past decision against present knowledge
    is hindsight, and hindsight is not evidence -- so this walks the supersession
    chain backwards and returns the version that was current at ``when``,
    together with a fresh verdict on it.

    It returns ``known: false`` rather than the nearest surviving version when
    the honest answer is "we held something else then and cannot show you what".
    ``unreconstructible`` names the digests that prove a version existed and
    whose body did not survive; if it is non-empty, the replay across that
    window is incomplete and says so.

    Args:
        when: ISO-8601 instant, e.g. "2026-03-01T14:02:00Z".
    """
    sess = _sess()
    timeline = Timeline(sess.store)
    envelope = timeline.as_of(category, name, when)
    lost = timeline.unreconstructible(category, name)
    payload: dict[str, Any] = {
        "ok": True,
        "as_of": when,
        "known": envelope is not None,
        "versions_held": len(timeline.versions(category, name)),
        "unreconstructible": [
            {k: v for k, v in record.items() if k != "extra"} for record in lost
        ],
    }
    if envelope is None:
        payload["note"] = (
            "Nothing this store can show was known at that moment. That is either "
            "because the memory did not exist yet, or because the version held "
            "then was overwritten without being archived -- see unreconstructible."
        )
        return fence(payload)
    payload["memory"] = memory_view(
        envelope, sess.gate.admit(envelope), category=category, name=name
    )
    return fence(payload)


# ----------------------------------------------------------------------
# The FLAGGED tier
# ----------------------------------------------------------------------
def admissible_flag(
    address_or_handle: str, reason: str, evidence: dict[str, Any]
) -> dict[str, Any]:
    """Put an actor in the FLAGGED tier. This survives into the next session.

    Flagging is about who is speaking, not about what was said. Once an actor is
    flagged, everything they sourced is refused with ``flagged_source`` without
    being re-litigated on its merits -- which is the point: an actor caught
    laundering forged evidence has told you what their assertions are worth.

    Both ``reason`` and ``evidence`` are required and neither may be empty. A
    block nobody can review is not a control, it is a grudge; a later reviewer
    has to be able to see what the actor did. Good evidence is the digest of the
    memory that failed and the verdict code it failed with.

    Flags are never deleted. Revoking one stamps the revocation into the record
    and leaves the row, because "we flagged them in March and cleared them in
    April" is a fact somebody will need.

    Args:
        address_or_handle: A 0x address is stored as an address; anything else
            is stored as a handle. Addresses are the stronger key -- they are
            what binds this tier to onchain identity.
    """
    if not reason or not reason.strip():
        _refuse(
            "VALIDATION_ERROR",
            "reason is required: an unexplained block is unreviewable, and this "
            "one outlives the session that made it.",
        )
    if not isinstance(evidence, dict) or not evidence:
        _refuse(
            "UNEVIDENCED_FLAG",
            "Refusing to flag on nothing. Pass evidence a reviewer can check -- "
            "the digest of the memory that failed and the verdict code it failed "
            "with is enough. This tier refuses money; it needs a reason on the "
            "record.",
            recovery="pass evidence such as {digest: '0x...', verdict: 'evidence_not_found'}",
        )

    sess = _sess()
    identifier = (address_or_handle or "").strip()
    if not identifier:
        _refuse("VALIDATION_ERROR", "address_or_handle is required.")
    address, handle = (identifier, None) if _is_address(identifier) else (None, identifier)
    flag_id = sess.flags.flag_actor(
        address=address, handle=handle, reason=reason, evidence=evidence
    )
    sess.invalidate()
    record = sess.flags.is_flagged(identifier)
    return {
        "ok": True,
        "flag_id": flag_id,
        "flagged": _flag_dict(record) if record else None,
        "note": (
            "In the FLAGGED tier from now on, in this database, across sessions "
            "and processes. Every memory this actor sourced now verdicts as "
            "flagged_source."
        ),
    }


def admissible_flags(include_revoked: bool = False) -> dict[str, Any]:
    """List the FLAGGED tier: who this agent refuses to be moved by, and why.

    Newest first. Revoked flags are hidden by default and are never deleted --
    pass ``include_revoked`` to see the full history, including who was cleared
    and on what grounds.
    """
    sess = _sess()
    records = sess.flags.list_flags(include_revoked=include_revoked)
    return {
        "ok": True,
        "count": len(records),
        "include_revoked": include_revoked,
        "flags": [_flag_dict(record) for record in records],
    }


# ----------------------------------------------------------------------
# Anchoring
# ----------------------------------------------------------------------
def admissible_anchor_preview() -> dict[str, Any]:
    """The Merkle root, leaf count and watermark that would be published now.

    An anchor is a public commitment to what this agent currently holds
    admissible, plus the transaction-time watermark it is complete to. It makes
    the store tamper-evident: a memory altered after an anchor no longer proves
    against it, and the anchor is immutable.

    Only admissible memories are committed. Anchoring everything would commit to
    hearsay and forgeries alongside evidence and make the root mean nothing -- an
    anchor is a claim about what the agent is willing to act on, not an
    inventory. Holding nothing admissible anchors the zero root with a leaf count
    of zero, which is a real position and worth publishing.

    Reads only. This tool never signs and never broadcasts: publishing is a
    deliberate act with a key, and it lives in the ``admissible anchor
    --publish`` command, not behind a tool a model can call.
    """
    sess = _sess()
    pairs: list[tuple[str, str]] = []
    excluded: dict[str, int] = {}
    for _, _, envelope in _all_memories(sess):
        verdict = sess.gate.admit(envelope)
        if verdict.admits:
            pairs.append((envelope.digest, envelope.provenance.observed_at))
        else:
            excluded[verdict.code.value] = excluded.get(verdict.code.value, 0) + 1

    commitment = commit(pairs)
    return {
        "ok": True,
        "root": commitment.root_hex,
        "leaf_count": commitment.leaf_count,
        "as_of": commitment.as_of,
        "excluded": dict(sorted(excluded.items())),
        "chain": sess.chain_status,
        "note": (
            "Nothing was signed or broadcast. Publish with the CLI: "
            "`admissible anchor --publish`, which requires PRIVATE_KEY in the "
            "environment and refuses without it."
        ),
    }


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------
def _memories_about(sess: Session, counterparty: str) -> list[tuple[str, str, Envelope]]:
    """Every parseable memory whose claim names this counterparty.

    Matched case-insensitively, because an address re-cased is the same address
    and an attacker who re-cases one is not a different attacker. Sorted oldest
    observation first so the lead refusal in a decision is the first attack that
    landed rather than whichever row SQLite returned first.
    """
    needle = (counterparty or "").strip().casefold()
    out: list[tuple[str, str, Envelope]] = []
    for category, name, envelope in _all_memories(sess, sess.settings.categories):
        claimed = envelope.claim.get("counterparty")
        if isinstance(claimed, str) and claimed.strip().casefold() == needle:
            out.append((category, name, envelope))
    out.sort(key=lambda item: (item[2].provenance.observed_at, item[0], item[1]))
    return out


def _all_memories(
    sess: Session, categories: tuple[str, ...] | None = None
) -> list[tuple[str, str, Envelope]]:
    """Parseable memories, with their location. Malformed rows are skipped here.

    Goes through ``list_entities`` rather than ``recall_many`` because the
    category and name are needed for citations, and ``recall_many`` returns the
    envelopes without saying where they came from.
    """
    out: list[tuple[str, str, Envelope]] = []
    for category in categories or (None,):
        for row in sess.store.client.list_entities(category, limit=MAX_SWEEP):
            parsed = sess.store.parse_body(row["category"], row["name"], row["body"])
            if isinstance(parsed, Envelope):
                out.append((row["category"], row["name"], parsed))
    return out


def _malformed_rows(sess: Session) -> list[MalformedMemory]:
    """Rows in the swept categories that are not envelopes at all.

    Surfaced with every decision rather than dropped. A row nobody can parse is
    a fact about the store, and a decision that silently ignored one would look
    more confident than it is.
    """
    out: list[MalformedMemory] = []
    for category in sess.settings.categories:
        for row in sess.store.client.list_entities(category, limit=MAX_SWEEP):
            parsed = sess.store.parse_body(row["category"], row["name"], row["body"])
            if isinstance(parsed, MalformedMemory):
                out.append(parsed)
    return out


def _flag_dict(record: Any) -> dict[str, Any]:
    return {
        "id": record.id,
        "actor_address": record.actor_address,
        "actor_handle": record.actor_handle,
        "flagged_at": record.flagged_at,
        "reason": record.reason,
        "evidence": scrub(record.evidence),
        "active": record.is_active,
        "revoked_at": record.revoked_at,
        "revoked_reason": record.revoked_reason,
        "address_valid": record.address_valid,
    }


def _is_address(value: str) -> bool:
    try:
        from eth_utils import is_address

        return bool(is_address(value))
    except Exception:  # noqa: BLE001 - a failed check falls back to "handle"
        return False


#: Every tool this server exposes, in the order a reader should meet them.
#: Registered rather than decorated so each one stays an ordinary function that
#: the tests -- and any Python caller -- can invoke without an MCP client.
TOOLS = (
    admissible_remember,
    admissible_recall,
    admissible_verify,
    admissible_verify_claim,
    admissible_decide,
    admissible_dossier,
    admissible_as_of,
    admissible_flag,
    admissible_flags,
    admissible_anchor_preview,
)


def _guarded(tool: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    """Wrap one tool so its result is re-checked on the way out.

    Every tool that surfaces memory already goes through
    :func:`~admissible_mcp.views.fence`, which guards. This runs the same check
    at the dispatch boundary, so a tool added later that assembles its own
    payload and forgets the fence fails loudly here rather than quietly shipping
    a claim with no verdict to a model that will read it as fact.

    ``functools.wraps`` matters more than it looks: the MCP SDK derives each
    tool's name, description and input schema from the function it is handed,
    and a wrapper without it would register ten tools called ``wrapper``.
    """

    @functools.wraps(tool)
    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = tool(*args, **kwargs)
        try:
            guard(result)
        except UnverdictedClaim as exc:
            _refuse("UNVERDICTED_CLAIM", str(exc))
        return result

    return wrapper


def build_server() -> Any:
    """Build the MCP server with all ten tools registered."""
    server = ToolServer(SERVER_NAME)
    for tool in TOOLS:
        server.tool()(_guarded(tool))
    return server


def run_stdio() -> None:
    """Run on stdio, which is what every desktop MCP client speaks."""
    build_server().run()


__all__ = [
    "SERVER_NAME",
    "TOOLS",
    "ToolError",
    "UnverdictedClaim",
    "admissible_anchor_preview",
    "admissible_as_of",
    "admissible_decide",
    "admissible_dossier",
    "admissible_flag",
    "admissible_flags",
    "admissible_recall",
    "admissible_remember",
    "admissible_verify",
    "admissible_verify_claim",
    "build_server",
    "run_stdio",
]
