"""The FLAGGED tier.

Sibyl Memory's ``schema.sql`` declares this table and comments it:

    -- FLAGGED tier: actors flagged for social-engineering / fraud (rule 13/14/15)

and then ships no API for it. ``client.py`` and ``storage.py`` contain zero
references to ``flagged_actors``; the only mention anywhere in the package is a
lint check that reads a column (``identifier``) the schema does not declare,
inside a bare ``except Exception: pass``. So the tier exists in the data model,
is documented in the comments, and is unreachable from the SDK.

This module implements it. Not as a side table and not as a JSON blob in an
entity body -- rows go into ``flagged_actors``, in the same database, under the
same tenant, so a second process opening the same file sees the blocklist with
no warm-up. That cold start is the point: a blocklist you have to rebuild is a
blocklist you do not have when it matters.

Two design notes worth stating out loud:

* **Addresses are normalised for lookup and preserved as given.** The column
  keeps exactly the string that was handed to us -- an operator reading the row
  later should see what was reported, checksum casing and all. Matching happens
  against a case-folded form, because an attacker who re-cases an address is not
  a different attacker.
* **Unflagging does not delete.** The table has no lifecycle column, so a
  revocation is recorded inside ``evidence`` and the row stays. Removing the row
  would destroy the record that the actor was once flagged, which is exactly the
  fact a later investigation needs. The journal gets an event either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eth_utils import is_address, to_normalized_address
from sibyl_memory_client.storage import dumps, loads, new_id

from .envelope import utcnow
from .store import AdmissibleStore

#: Marker key inside ``flagged_actors.evidence`` for our metadata wrapper. The
#: column is free-form JSON; a namespace keeps the caller's evidence and our
#: bookkeeping from colliding.
FLAG_ENVELOPE_VERSION = 1


def _norm(value: str | None) -> str | None:
    """Case-folded lookup form. ``None`` stays ``None``."""
    if value is None:
        return None
    value = value.strip()
    return value.casefold() if value else None


def _norm_actor(value: str | None) -> str | None:
    """Like :func:`_norm`, but EVM addresses go through eth-utils.

    A checksummed address and its lowercase form are the same account; letting
    ``eth_utils`` do that reduction means we agree with every other tool in the
    stack about what "the same address" means.
    """
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        if is_address(value):
            return to_normalized_address(value)
    except (ValueError, TypeError):  # pragma: no cover - eth-utils is defensive already
        pass
    return value.casefold()


@dataclass(frozen=True, slots=True)
class FlagRecord:
    """One row of the FLAGGED tier."""

    id: str
    #: Exactly the strings we were given, not the normalised ones.
    actor_address: str | None
    actor_handle: str | None
    flagged_at: str
    reason: str
    #: The caller's evidence blob, unwrapped from our metadata envelope.
    evidence: dict[str, Any] = field(default_factory=dict)
    revoked_at: str | None = None
    revoked_reason: str | None = None
    #: Whether the address parsed as a well-formed EVM address when flagged.
    address_valid: bool = False

    @property
    def is_active(self) -> bool:
        """A revoked flag is history, not a live block."""
        return self.revoked_at is None

    @property
    def lookup_keys(self) -> tuple[str, ...]:
        """The normalised forms this record answers to."""
        return tuple(
            k for k in (_norm_actor(self.actor_address), _norm(self.actor_handle)) if k
        )


class FlaggedActors:
    """Read and write Sibyl's FLAGGED tier."""

    def __init__(self, store: AdmissibleStore) -> None:
        self._store = store

    # ------------------------------------------------------------------
    def flag_actor(
        self,
        address: str | None = None,
        handle: str | None = None,
        *,
        reason: str,
        evidence: dict[str, Any] | None = None,
        flagged_at: str | None = None,
    ) -> str:
        """Flag an actor. Returns the new row id.

        At least one of ``address`` / ``handle`` is required: a flag nobody can
        be matched against is a note to self, and this table is a control.
        ``flagged_at`` is injectable so a backfill can carry the real time
        rather than the import time.
        """
        if not (address or handle):
            raise ValueError("flag_actor needs an address or a handle to flag")
        if not reason or not reason.strip():
            raise ValueError("flag_actor needs a reason: an unexplained block is unreviewable")

        evidence = dict(evidence or {})
        flag_id = new_id()
        ts = flagged_at or utcnow()
        wrapper = {
            "v": FLAG_ENVELOPE_VERSION,
            "evidence": evidence,
            "normalized": {
                "address": _norm_actor(address),
                "handle": _norm(handle),
                "address_valid": bool(address and is_address(address)),
            },
        }

        with self._store.client.storage.transaction() as conn:
            conn.execute(
                "INSERT INTO flagged_actors "
                "(id, tenant_id, actor_handle, actor_address, flagged_at, reason, evidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    flag_id,
                    self._store.tenant_id,
                    handle,
                    address,
                    ts,
                    reason,
                    dumps(wrapper),
                ),
            )

        self._store.journal_write(
            "flag",
            flag_id=flag_id,
            actor_address=address,
            actor_handle=handle,
            reason=reason,
            flagged_at=ts,
            evidence_keys=sorted(evidence),
        )
        return flag_id

    def unflag(self, flag_id: str, reason: str) -> bool:
        """Revoke a flag without erasing it. Returns False if there is no such flag.

        The row survives with a revocation stamped into its evidence, so "we
        flagged them in March and cleared them in April" stays answerable. The
        journal event is the durable record of the decision.
        """
        if not reason or not reason.strip():
            raise ValueError("unflag needs a reason: a silent unblock is unreviewable")

        row = self._row(flag_id)
        if row is None:
            return False
        wrapper = self._wrapper(row["evidence"])
        if wrapper.get("revoked"):
            return True  # already revoked; idempotent, and the first reason stands

        ts = utcnow()
        wrapper["revoked"] = {"at": ts, "reason": reason}
        with self._store.client.storage.transaction() as conn:
            conn.execute(
                "UPDATE flagged_actors SET evidence = ? WHERE id = ? AND tenant_id = ?",
                (dumps(wrapper), flag_id, self._store.tenant_id),
            )

        self._store.journal_write(
            "unflag",
            flag_id=flag_id,
            actor_address=row["actor_address"],
            actor_handle=row["actor_handle"],
            reason=reason,
            revoked_at=ts,
        )
        return True

    # ------------------------------------------------------------------
    def is_flagged(self, address_or_handle: str) -> FlagRecord | None:
        """The live flag for this actor, or ``None``.

        Matches against both columns: callers frequently hold one identifier and
        do not know which kind it is, and a lookup that silently checks only
        half the table fails open.
        """
        needle = _norm_actor(address_or_handle)
        if not needle:
            return None
        alt = _norm(address_or_handle)

        for rec in self._select(needle, alt):
            if rec.is_active:
                return rec
        return None

    def list_flags(
        self, *, include_revoked: bool = False, limit: int | None = None
    ) -> list[FlagRecord]:
        """All flags for this tenant, newest first."""
        with self._store.client.storage.connection() as conn:
            rows = conn.execute(
                "SELECT id, actor_handle, actor_address, flagged_at, reason, evidence "
                "FROM flagged_actors WHERE tenant_id = ? "
                "ORDER BY flagged_at DESC, rowid DESC",
                (self._store.tenant_id,),
            ).fetchall()
        out = [self._to_record(r) for r in rows]
        if not include_revoked:
            out = [r for r in out if r.is_active]
        return out[:limit] if limit is not None else out

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _select(self, needle: str, alt: str | None) -> list[FlagRecord]:
        """Indexed fast path, with a full-tenant fallback for non-ASCII handles.

        SQLite's ``lower()`` only folds ASCII, so a handle like ``RUGPULLER``
        matches in SQL but ``RÜGPULLER`` would not. The fallback scan uses
        Python's ``casefold`` and only runs when the fast path misses, which
        keeps the common case one indexed query.
        """
        with self._store.client.storage.connection() as conn:
            rows = conn.execute(
                "SELECT id, actor_handle, actor_address, flagged_at, reason, evidence "
                "FROM flagged_actors WHERE tenant_id = ? "
                "AND (lower(actor_address) = ? OR lower(actor_handle) = ? "
                "     OR lower(actor_address) = ? OR lower(actor_handle) = ?) "
                "ORDER BY flagged_at DESC, rowid DESC",
                (self._store.tenant_id, needle, needle, alt or needle, alt or needle),
            ).fetchall()
            if not rows and not needle.isascii():
                rows = conn.execute(
                    "SELECT id, actor_handle, actor_address, flagged_at, reason, evidence "
                    "FROM flagged_actors WHERE tenant_id = ? "
                    "ORDER BY flagged_at DESC, rowid DESC",
                    (self._store.tenant_id,),
                ).fetchall()
                return [
                    rec
                    for rec in (self._to_record(r) for r in rows)
                    if needle in rec.lookup_keys or (alt and alt in rec.lookup_keys)
                ]
        return [self._to_record(r) for r in rows]

    def _row(self, flag_id: str):
        with self._store.client.storage.connection() as conn:
            return conn.execute(
                "SELECT id, actor_handle, actor_address, flagged_at, reason, evidence "
                "FROM flagged_actors WHERE id = ? AND tenant_id = ?",
                (flag_id, self._store.tenant_id),
            ).fetchone()

    @staticmethod
    def _wrapper(blob: str | None) -> dict[str, Any]:
        """Unpack our evidence envelope, tolerating rows we did not write."""
        raw = loads(blob) if blob else None
        if isinstance(raw, dict) and raw.get("v") == FLAG_ENVELOPE_VERSION:
            return dict(raw)
        # A row written by something else: treat the whole blob as evidence.
        return {"v": FLAG_ENVELOPE_VERSION, "evidence": raw if isinstance(raw, dict) else {}}

    @classmethod
    def _to_record(cls, row) -> FlagRecord:
        wrapper = cls._wrapper(row["evidence"])
        revoked = wrapper.get("revoked") or {}
        normalized = wrapper.get("normalized") or {}
        return FlagRecord(
            id=row["id"],
            actor_address=row["actor_address"],
            actor_handle=row["actor_handle"],
            flagged_at=row["flagged_at"],
            reason=row["reason"] or "",
            evidence=wrapper.get("evidence") or {},
            revoked_at=revoked.get("at"),
            revoked_reason=revoked.get("reason"),
            address_valid=bool(normalized.get("address_valid")),
        )
