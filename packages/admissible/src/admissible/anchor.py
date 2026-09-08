"""Committing the memory to chain.

The store is a SQLite file on one machine. Anyone with write access to it can
rewrite what the agent remembers, and nothing in the file itself would show that
happened. Anchoring closes that gap: at intervals the agent publishes a Merkle
root over the digests of every memory it currently holds admissible, together
with the transaction-time watermark those memories were current at.

What that buys, concretely:

* **Tamper evidence.** A memory altered after an anchor no longer proves against
  it, and the anchor is immutable and public.
* **Answerable time-travel.** ``as_of`` replay is only as trustworthy as the
  store replaying it. With anchors, "here is what I knew at 14:02" is a claim a
  stranger can check rather than one they have to take on faith.
* **An honest empty state.** An agent holding nothing admissible anchors the
  zero root with a leaf count of zero. Publishing "I have no evidence" is a
  real position, and the contract treats it as one.

The tree must agree with ``AdmissibilityAnchor.sol`` bit for bit, so the shape
is fixed here and mirrored in a test rather than being left to convention:

* ``leaf = keccak256(digest_bytes)`` -- a second hash over the 32-byte digest.
  Leaves hash a 32-byte preimage, internal nodes a 64-byte one, and that length
  difference is what stops an attacker submitting an internal node as a leaf.
* internal nodes are ``keccak256(min(a,b) || max(a,b))`` -- sorted pairs, so a
  proof carries no direction bits.
* an odd node at the end of a level is promoted to the next level unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from eth_utils import keccak

ZERO32 = b"\x00" * 32


def _to_bytes32(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        raw = value
    else:
        text = value[2:] if value.startswith(("0x", "0X")) else value
        raw = bytes.fromhex(text)
    if len(raw) != 32:
        raise ValueError(f"expected a 32-byte digest, got {len(raw)} bytes")
    return raw


def leaf_of(digest: str | bytes) -> bytes:
    """The canonical leaf for a memory digest, matching ``leafOf`` onchain."""
    return keccak(_to_bytes32(digest))


def _hash_pair(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a <= b else keccak(b + a)


@dataclass(frozen=True)
class MerkleTree:
    """A committed set of memory digests, with proofs."""

    #: Leaves in insertion order, after sorting and de-duplication of digests.
    leaves: tuple[bytes, ...]
    #: Level 0 is the leaves; the last level holds the single root.
    levels: tuple[tuple[bytes, ...], ...]

    @property
    def root(self) -> bytes:
        if not self.leaves:
            return ZERO32
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return "0x" + self.root.hex()

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    def proof(self, digest: str | bytes) -> list[bytes]:
        """Sibling path for one digest. Raises KeyError if it is not committed."""
        leaf = leaf_of(digest)
        try:
            index = self.leaves.index(leaf)
        except ValueError as exc:
            raise KeyError(f"digest not in this tree: {digest!r}") from exc

        path: list[bytes] = []
        for level in self.levels[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                path.append(level[sibling])
            # An odd node with no sibling is promoted unchanged, so it
            # contributes nothing to the path -- which is why the proof for a
            # single-leaf tree is empty.
            index //= 2
        return path

    def proof_hex(self, digest: str | bytes) -> list[str]:
        return ["0x" + node.hex() for node in self.proof(digest)]

    def verify(self, digest: str | bytes, proof: Sequence[bytes]) -> bool:
        """Local mirror of the onchain check, for tests and for the demo."""
        if not self.leaves:
            return False
        node = leaf_of(digest)
        if node == ZERO32:
            return False
        for sibling in proof:
            node = _hash_pair(node, sibling)
        return node == self.root


def build_tree(digests: Iterable[str | bytes]) -> MerkleTree:
    """Commit a set of memory digests.

    Digests are sorted and de-duplicated first, so the root depends only on the
    *set* of admissible memories and not on the order they happened to be
    recalled in. Two agents holding the same evidence publish the same root,
    which is what makes roots comparable at all.
    """
    unique = sorted({_to_bytes32(d) for d in digests})
    leaves = tuple(leaf_of(d) for d in unique)
    if not leaves:
        return MerkleTree(leaves=(), levels=())

    levels: list[tuple[bytes, ...]] = [leaves]
    current = list(leaves)
    while len(current) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(current) - 1, 2):
            nxt.append(_hash_pair(current[i], current[i + 1]))
        if len(current) % 2:
            nxt.append(current[-1])
        levels.append(tuple(nxt))
        current = nxt
    return MerkleTree(leaves=leaves, levels=tuple(levels))


@dataclass(frozen=True)
class Commitment:
    """Everything needed to publish one anchor and to prove against it later."""

    root_hex: str
    leaf_count: int
    #: Transaction-time watermark: the newest ``observed_at`` in the set. The
    #: contract enforces that this never goes backwards, which is the guarantee
    #: that makes an anchor history readable as a timeline rather than a pile.
    as_of: str
    tree: MerkleTree
    digests: tuple[str, ...]

    @property
    def as_of_unix(self) -> int:
        from datetime import datetime

        return int(
            datetime.fromisoformat(self.as_of.replace("Z", "+00:00")).timestamp()
        )


def commit(admissible_memories: Sequence[tuple[str, str]]) -> Commitment:
    """Build the commitment for a set of ``(digest, observed_at)`` pairs.

    Only admissible memories belong here. Anchoring everything the store holds
    would commit to hearsay and forgeries alongside evidence, which would make
    the root mean nothing -- an anchor is a claim about what the agent is
    willing to act on, not an inventory.
    """
    digests = tuple(d for d, _ in admissible_memories)
    tree = build_tree(digests)
    watermark = max((ts for _, ts in admissible_memories), default="1970-01-01T00:00:00.000Z")
    return Commitment(
        root_hex=tree.root_hex,
        leaf_count=tree.leaf_count,
        as_of=watermark,
        tree=tree,
        digests=digests,
    )
