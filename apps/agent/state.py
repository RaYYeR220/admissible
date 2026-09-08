"""The graph's state, and the vocabulary the store is organised around.

Two notes about the shape.

The state carries *objects* -- envelopes, verdicts, a decision, a receipt --
rather than dictionaries. There is no checkpointer (``SibylStore`` is a
long-term store, not a checkpointer, and serialising graph state into an
entity/event schema would be a poor fit), so nothing here has to survive a
round trip through JSON. Keeping the real objects means the ``decide`` node
receives the same ``Verdict`` the gate produced rather than a copy of its
fields, and a copy of a verdict is exactly the kind of thing that gets edited.

The refused memories stay in the state all the way to the end. They are not
noise to be filtered before the interesting part; on an attack run they *are*
the interesting part, and an agent that drops them looks confident in the one
situation where confidence is the failure.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

#: Per-job records. ``admissible.consolidate`` folds this category into dossiers.
INTERACTION_CATEGORY = "interaction"
#: What third parties say about a counterparty. Everything an attacker writes
#: lands here, alongside things honest peers write. They are indistinguishable
#: by category on purpose -- the distinction the system makes is provenance.
TESTIMONIAL_CATEGORY = "testimonial"
#: Folded dossiers, one per counterparty.
DOSSIER_CATEGORY = "dossier"
#: Graph nodes for actors, so relations can point at them.
ACTOR_CATEGORY = "actor"

#: Categories ``recall`` sweeps for memories about a counterparty.
RECALL_CATEGORIES = (INTERACTION_CATEGORY, TESTIMONIAL_CATEGORY, DOSSIER_CATEGORY)

#: Categories holding records the agent *computed* rather than learned. They are
#: recalled and judged like anything else, and they are kept out of the credit
#: arithmetic, because a fold of memories is not a memory: weighing it would
#: count its own inputs a second time, and a refusal of one would make an
#: arithmetic artefact look like somebody's attack.
DERIVED_CATEGORIES = (DOSSIER_CATEGORY,)


class BuyerState(TypedDict, total=False):
    """One pass of the buyer graph over one offer."""

    # -- perceive
    counterparty: str
    counterparty_handle: str | None
    requested_usd: float
    service: str
    pitch: str
    job: dict[str, Any]
    request: dict[str, Any]
    #: The model's advisory proposal. Read by the log and by nothing else.
    proposal: dict[str, Any]

    # -- recall
    #: ``(category, name, Envelope)`` for everything about this counterparty
    #: that the agent learned from somewhere.
    recalled: list[Any]
    #: The same shape, for records the agent computed from the ones above.
    derived: list[Any]
    #: Rows that are not parseable envelopes. Kept: an unreadable memory is a
    #: refusal with a location, not a row to skip quietly.
    malformed: list[dict[str, Any]]
    #: Whether this counterparty is in the FLAGGED tier, and why.
    flagged: dict[str, Any] | None
    posture: dict[str, Any]

    # -- admit
    #: ``(Envelope, Verdict)`` pairs, admitted and refused alike.
    judged: list[Any]
    #: Verdicts on the derived records, reported and never weighed.
    judged_derived: list[dict[str, Any]]

    # -- decide / act
    decision: Any
    receipt: Any

    # -- attest / reflect / consolidate
    narration: str
    flags_raised: list[dict[str, Any]]
    contaminated: list[dict[str, Any]]
    posture_after: dict[str, Any]
    dossier: dict[str, Any]

    #: Append-only trace of what each node did, for the demo's printed blocks.
    log: Annotated[list[str], operator.add]
