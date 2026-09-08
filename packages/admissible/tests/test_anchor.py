"""The Python tree and the Solidity contract have to agree exactly.

They are two independent implementations of the same commitment, and a
disagreement would not show up as an error -- it would show up as an anchor that
proves nothing, quietly, in production. So the offline tests pin the shape and
the marked test settles it against the real contract on a local node.

Run the differential with a node up:

    anvil --silent --port 8546 &
    forge create src/AdmissibilityAnchor.sol:AdmissibilityAnchor \\
        --rpc-url http://127.0.0.1:8546 --private-key <anvil key 0> --broadcast
    ANCHOR_ADDRESS=0x... pytest -m anvil
"""

from __future__ import annotations

import os
import random
import subprocess
import time

import pytest

from admissible.anchor import ZERO32, build_tree, commit, leaf_of

ANVIL_RPC = os.environ.get("ANVIL_RPC", "http://127.0.0.1:8546")
ANVIL_KEY = os.environ.get(
    "ANVIL_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
ANVIL_AGENT = os.environ.get("ANVIL_AGENT", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


def digests(n: int, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    return ["0x" + bytes(rng.randrange(256) for _ in range(32)).hex() for _ in range(n)]


# -- shape ---------------------------------------------------------------------


def test_an_empty_commitment_is_a_real_position():
    """Holding no admissible memory is a claim worth publishing, not an error."""
    tree = build_tree([])
    assert tree.root == ZERO32
    assert tree.leaf_count == 0
    # And nothing proves against it, which is what stops a zero leaf with an
    # empty proof from matching the zero root.
    assert tree.verify("0x" + "00" * 32, []) is False


def test_a_single_leaf_needs_no_proof():
    d = digests(1)[0]
    tree = build_tree([d])
    assert tree.proof(d) == []
    assert tree.verify(d, []) is True


def test_the_root_depends_on_the_set_not_the_order():
    """Two agents holding the same evidence must publish the same root."""
    ds = digests(6)
    assert build_tree(ds).root == build_tree(list(reversed(ds))).root


def test_duplicates_do_not_change_the_commitment():
    ds = digests(4)
    assert build_tree(ds).root == build_tree(ds + ds[:2]).root
    assert build_tree(ds + ds[:2]).leaf_count == 4


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 9, 17, 33])
def test_every_leaf_proves_against_its_own_root(n):
    ds = digests(n)
    tree = build_tree(ds)
    assert tree.leaf_count == n
    for d in ds:
        assert tree.verify(d, tree.proof(d)) is True


@pytest.mark.parametrize("n", [2, 3, 5, 9])
def test_a_foreign_leaf_never_proves(n):
    """The negative control. Without it, a passing proof means nothing."""
    ds = digests(n)
    tree = build_tree(ds)
    outsider = digests(1, seed=999)[0]
    assert tree.verify(outsider, tree.proof(ds[0])) is False


def test_a_corrupted_sibling_breaks_the_proof():
    ds = digests(8)
    tree = build_tree(ds)
    proof = tree.proof(ds[3])
    assert proof, "an 8-leaf tree must give a non-empty path"
    tampered = list(proof)
    tampered[0] = bytes([tampered[0][0] ^ 0xFF]) + tampered[0][1:]
    assert tree.verify(ds[3], tampered) is False


def test_an_uncommitted_digest_has_no_proof():
    tree = build_tree(digests(4))
    with pytest.raises(KeyError):
        tree.proof(digests(1, seed=123)[0])


def test_leaves_are_hashed_once_more_than_the_digest():
    """Leaves and internal nodes must have different preimage lengths.

    Without that separation an attacker could present an internal node as a
    leaf and prove membership of something that was never committed.
    """
    d = "0x" + "11" * 32
    assert leaf_of(d) != bytes.fromhex("11" * 32)
    assert len(leaf_of(d)) == 32


def test_the_watermark_is_the_newest_observation():
    c = commit(
        [
            ("0x" + "01" * 32, "2026-09-01T00:00:00.000Z"),
            ("0x" + "02" * 32, "2026-09-08T12:00:00.000Z"),
            ("0x" + "03" * 32, "2026-09-05T00:00:00.000Z"),
        ]
    )
    assert c.as_of == "2026-09-08T12:00:00.000Z"
    assert c.leaf_count == 3


def test_a_short_digest_is_refused_rather_than_padded():
    with pytest.raises(ValueError):
        build_tree(["0xdeadbeef"])


# -- the differential ----------------------------------------------------------


@pytest.mark.anvil
@pytest.mark.skipif(
    not os.environ.get("ANCHOR_ADDRESS"),
    reason="set ANCHOR_ADDRESS to run against a deployed contract",
)
@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 9, 17])
def test_the_contract_accepts_our_proofs(n):
    """Every proof this module builds must verify inside the contract."""
    address = os.environ["ANCHOR_ADDRESS"]
    ds = digests(n, seed=n * 13)
    tree = build_tree(ds)

    assert _cast(
        "call", address, "leafOf(bytes32)(bytes32)", ds[0], "--rpc-url", ANVIL_RPC
    ) == "0x" + leaf_of(ds[0]).hex()

    # The contract refuses an asOf that goes backwards, which is the point of
    # the anchor history. A wall-clock watermark keeps successive test runs
    # against the same node moving forward instead of colliding.
    before = _anchor_count(address)
    _cast(
        "send", address, "anchor(bytes32,uint64,uint32)",
        tree.root_hex, str(int(time.time()) + n), str(tree.leaf_count),
        "--rpc-url", ANVIL_RPC, "--private-key", ANVIL_KEY,
    )
    assert _anchor_count(address) == before + 1, (
        "the anchor transaction did not land -- a reverted send still exits zero, "
        "so without this check the proofs below would be tested against a stale root"
    )

    for d in ds:
        proof = "[" + ",".join(tree.proof_hex(d)) + "]"
        verified = _cast(
            "call", address, "verifyLatest(address,bytes32,bytes32[])(bool)",
            ANVIL_AGENT, "0x" + leaf_of(d).hex(), proof, "--rpc-url", ANVIL_RPC,
        )
        assert verified == "true", f"contract rejected a proof we built for {d}"

    outsider = digests(1, seed=n * 977)[0]
    rejected = _cast(
        "call", address, "verifyLatest(address,bytes32,bytes32[])(bool)",
        ANVIL_AGENT, "0x" + leaf_of(outsider).hex(),
        "[" + ",".join(tree.proof_hex(ds[0])) + "]", "--rpc-url", ANVIL_RPC,
    )
    assert rejected == "false", "contract accepted a leaf that was never committed"


def _anchor_count(address: str) -> int:
    return int(
        _cast(
            "call", address, "anchorCount(address)(uint256)", ANVIL_AGENT,
            "--rpc-url", ANVIL_RPC,
        ).split()[0]
    )


def _cast(*args: str) -> str:
    result = subprocess.run(["cast", *args], capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(f"cast {args[0]} failed: {result.stderr[:400]}")
    return result.stdout.strip()
