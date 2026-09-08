// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {AdmissibilityAnchor} from "../src/AdmissibilityAnchor.sol";

/// @dev Reference Merkle tree builder, mirroring what the offchain (Python) client does: leaves
///      are already hashed, internal nodes use sorted-pair keccak256, and a lone node at the end
///      of an odd level is promoted unchanged. Kept in the tests only - the contract itself never
///      builds trees, it only verifies them.
library MerkleBuilder {
    function hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function nextLevel(bytes32[] memory level) internal pure returns (bytes32[] memory next) {
        uint256 width = (level.length + 1) / 2;
        next = new bytes32[](width);
        for (uint256 i = 0; i < width; ++i) {
            uint256 left = 2 * i;
            uint256 right = left + 1;
            next[i] = right < level.length ? hashPair(level[left], level[right]) : level[left];
        }
    }

    function root(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length != 0, "MerkleBuilder: empty tree has no root");
        bytes32[] memory level = leaves;
        while (level.length > 1) {
            level = nextLevel(level);
        }
        return level[0];
    }

    function proof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory out) {
        bytes32[] memory scratch = new bytes32[](256);
        uint256 count = 0;
        bytes32[] memory level = leaves;
        uint256 cursor = index;

        while (level.length > 1) {
            uint256 sibling = cursor ^ 1;
            if (sibling < level.length) {
                scratch[count] = level[sibling];
                ++count;
            }
            cursor /= 2;
            level = nextLevel(level);
        }

        out = new bytes32[](count);
        for (uint256 i = 0; i < count; ++i) {
            out[i] = scratch[i];
        }
    }

    function copy(bytes32[] memory input) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            out[i] = input[i];
        }
    }
}

abstract contract AnchorTestBase is Test {
    AdmissibilityAnchor internal anchors;

    address internal constant AGENT_A = address(0xA6E7A);
    address internal constant AGENT_B = address(0xB0B);

    function setUp() public virtual {
        anchors = new AdmissibilityAnchor();
        vm.warp(1_700_000_000);
        vm.roll(20_000_000);
    }

    /// @dev `count` distinct, deterministic leaves in the canonical leaf encoding.
    function _leaves(uint256 seed, uint256 count) internal pure returns (bytes32[] memory leaves) {
        leaves = new bytes32[](count);
        for (uint256 i = 0; i < count; ++i) {
            leaves[i] = keccak256(abi.encodePacked(keccak256(abi.encode("memory", seed, i))));
        }
    }
}

// =========================================================================================
// Anchoring
// =========================================================================================

contract AnchoringTest is AnchorTestBase {
    function test_AnchorStoresTheFullRecord() public {
        bytes32 root = keccak256("root-1");

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1_699_999_000, 7);

        assertEq(index, 0, "first anchor should be index 0");
        assertEq(anchors.anchorCount(AGENT_A), 1);

        AdmissibilityAnchor.Anchor memory stored = anchors.getAnchor(AGENT_A, 0);
        assertEq(stored.root, root);
        assertEq(stored.asOf, 1_699_999_000);
        assertEq(stored.leafCount, 7);
        assertEq(stored.anchoredAt, 1_700_000_000, "anchoredAt must be block.timestamp");
        assertEq(stored.blockNumber, 20_000_000, "blockNumber must be block.number");
        assertEq(stored.agent, AGENT_A, "agent must be msg.sender");
    }

    function test_AnchorEmitsMemoryAnchored() public {
        bytes32 root = keccak256("root-event");

        vm.expectEmit(true, true, true, true, address(anchors));
        emit AdmissibilityAnchor.MemoryAnchored(AGENT_A, 0, root, 1_699_999_500, 3, 1_700_000_000, 20_000_000);

        vm.prank(AGENT_A);
        anchors.anchor(root, 1_699_999_500, 3);
    }

    function test_AnchorAppendsAndReturnsIncrementingIndex() public {
        vm.startPrank(AGENT_A);
        assertEq(anchors.anchor(keccak256("r0"), 100, 1), 0);
        assertEq(anchors.anchor(keccak256("r1"), 200, 2), 1);
        assertEq(anchors.anchor(keccak256("r2"), 300, 3), 2);
        vm.stopPrank();

        assertEq(anchors.anchorCount(AGENT_A), 3);
        assertEq(anchors.getAnchor(AGENT_A, 0).root, keccak256("r0"));
        assertEq(anchors.getAnchor(AGENT_A, 2).root, keccak256("r2"));
    }

    function test_AnchorAcceptsTheEmptyCommitment() public {
        vm.prank(AGENT_A);
        anchors.anchor(bytes32(0), 100, 0);

        AdmissibilityAnchor.Anchor memory stored = anchors.getAnchor(AGENT_A, 0);
        assertEq(stored.root, bytes32(0));
        assertEq(stored.leafCount, 0);
    }

    function test_AnchorRevertsWhenLeavesHaveNoRoot() public {
        vm.prank(AGENT_A);
        vm.expectRevert(
            abi.encodeWithSelector(AdmissibilityAnchor.RootLeafCountMismatch.selector, bytes32(0), uint32(5))
        );
        anchors.anchor(bytes32(0), 100, 5);
    }

    function test_AnchorRevertsWhenRootHasNoLeaves() public {
        bytes32 root = keccak256("phantom");
        vm.prank(AGENT_A);
        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.RootLeafCountMismatch.selector, root, uint32(0)));
        anchors.anchor(root, 100, 0);
    }

    function test_AnchorAllowsAnUnchangedWatermark() public {
        vm.startPrank(AGENT_A);
        anchors.anchor(keccak256("r0"), 500, 1);
        anchors.anchor(keccak256("r1"), 500, 2);
        vm.stopPrank();

        assertEq(anchors.anchorCount(AGENT_A), 2);
        assertEq(anchors.getAnchor(AGENT_A, 1).asOf, 500);
    }

    function test_AnchorRevertsOnAsOfRegression() public {
        vm.startPrank(AGENT_A);
        anchors.anchor(keccak256("r0"), 1000, 1);

        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.AsOfRegression.selector, uint64(1000), uint64(999)));
        anchors.anchor(keccak256("r1"), 999, 1);
        vm.stopPrank();

        assertEq(anchors.anchorCount(AGENT_A), 1, "the rejected anchor must not be recorded");
    }

    function test_AnchorRegressionCheckLooksOnlyAtTheLastEntry() public {
        vm.startPrank(AGENT_A);
        anchors.anchor(keccak256("r0"), 100, 1);
        anchors.anchor(keccak256("r1"), 900, 1);

        // 500 is newer than the first anchor but older than the newest one: still a regression.
        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.AsOfRegression.selector, uint64(900), uint64(500)));
        anchors.anchor(keccak256("r2"), 500, 1);
        vm.stopPrank();
    }

    function testFuzz_AsOfMonotonicityIsEnforcedForEveryPair(uint64 first, uint64 second) public {
        vm.startPrank(AGENT_A);
        anchors.anchor(keccak256("r0"), first, 1);

        if (second < first) {
            vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.AsOfRegression.selector, first, second));
            anchors.anchor(keccak256("r1"), second, 1);
            assertEq(anchors.anchorCount(AGENT_A), 1);
        } else {
            anchors.anchor(keccak256("r1"), second, 1);
            assertEq(anchors.anchorCount(AGENT_A), 2);
        }
        vm.stopPrank();
    }

    function test_GetAnchorRevertsOutOfRange() public {
        vm.prank(AGENT_A);
        anchors.anchor(keccak256("r0"), 100, 1);

        vm.expectRevert(
            abi.encodeWithSelector(AdmissibilityAnchor.AnchorIndexOutOfRange.selector, AGENT_A, uint256(1), uint256(1))
        );
        anchors.getAnchor(AGENT_A, 1);
    }

    function test_LatestAnchorReturnsTheNewestEntry() public {
        vm.startPrank(AGENT_A);
        anchors.anchor(keccak256("r0"), 100, 1);
        anchors.anchor(keccak256("r1"), 200, 2);
        vm.stopPrank();

        (uint256 index, AdmissibilityAnchor.Anchor memory stored) = anchors.latestAnchor(AGENT_A);
        assertEq(index, 1);
        assertEq(stored.root, keccak256("r1"));
        assertEq(stored.asOf, 200);
    }

    function test_LatestAnchorRevertsForASilentAgent() public {
        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NoAnchors.selector, AGENT_B));
        anchors.latestAnchor(AGENT_B);
    }
}

// =========================================================================================
// Inclusion proofs
// =========================================================================================

contract InclusionProofTest is AnchorTestBase {
    function test_LeafOfIsTheDoubleHashConvention() public view {
        bytes32 digest = keccak256("claim: acme-agent delivered on time, tx 0xdead");
        assertEq(anchors.leafOf(digest), keccak256(abi.encodePacked(digest)));
    }

    function test_VerifyEveryLeafOfABalancedTree() public {
        bytes32[] memory leaves = _leaves(1, 8);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 8);

        for (uint256 i = 0; i < leaves.length; ++i) {
            assertTrue(
                anchors.verifyMemory(AGENT_A, index, leaves[i], MerkleBuilder.proof(leaves, i)),
                "every leaf must verify"
            );
        }
    }

    function test_VerifyEveryLeafOfAnUnbalancedTree() public {
        bytes32[] memory leaves = _leaves(2, 5);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 5);

        for (uint256 i = 0; i < leaves.length; ++i) {
            assertTrue(anchors.verifyMemory(AGENT_A, index, leaves[i], MerkleBuilder.proof(leaves, i)));
        }
    }

    /// @dev Negative control: a well-formed proof for a leaf the agent never anchored.
    function test_VerifyFailsForALeafThatIsNotInTheTree() public {
        bytes32[] memory leaves = _leaves(3, 8);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 8);

        bytes32 outsider = keccak256(abi.encodePacked(keccak256("memory the agent never held")));
        bytes32[] memory proof = MerkleBuilder.proof(leaves, 3);

        assertFalse(anchors.verifyMemory(AGENT_A, index, outsider, proof), "a foreign leaf must not verify");
    }

    /// @dev Negative control: a genuine leaf carried by a proof with one corrupted sibling.
    function test_VerifyFailsForACorruptedProof() public {
        bytes32[] memory leaves = _leaves(4, 8);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 8);

        bytes32[] memory proof = MerkleBuilder.proof(leaves, 5);
        assertTrue(anchors.verifyMemory(AGENT_A, index, leaves[5], proof), "sanity: the untouched proof verifies");

        bytes32[] memory corrupted = MerkleBuilder.copy(proof);
        corrupted[0] = bytes32(uint256(corrupted[0]) ^ 1);
        assertFalse(anchors.verifyMemory(AGENT_A, index, leaves[5], corrupted));
    }

    function test_VerifyFailsForATruncatedProof() public {
        bytes32[] memory leaves = _leaves(5, 8);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 8);

        bytes32[] memory proof = MerkleBuilder.proof(leaves, 2);
        bytes32[] memory truncated = new bytes32[](proof.length - 1);
        for (uint256 i = 0; i < truncated.length; ++i) {
            truncated[i] = proof[i];
        }

        assertFalse(anchors.verifyMemory(AGENT_A, index, leaves[2], truncated));
    }

    function test_VerifyFailsForAnOverlongProof() public {
        bytes32[] memory leaves = _leaves(6, 4);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 4);

        bytes32[] memory proof = MerkleBuilder.proof(leaves, 1);
        bytes32[] memory extended = new bytes32[](proof.length + 1);
        for (uint256 i = 0; i < proof.length; ++i) {
            extended[i] = proof[i];
        }
        extended[proof.length] = keccak256("extra");

        assertFalse(anchors.verifyMemory(AGENT_A, index, leaves[1], extended));
    }

    function test_SingleLeafTreeVerifiesWithAnEmptyProof() public {
        bytes32[] memory leaves = _leaves(7, 1);
        bytes32 root = MerkleBuilder.root(leaves);
        assertEq(root, leaves[0], "a one-leaf tree is its own root");

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 1);

        bytes32[] memory empty = new bytes32[](0);
        assertTrue(anchors.verifyMemory(AGENT_A, index, leaves[0], empty));
        assertFalse(anchors.verifyMemory(AGENT_A, index, keccak256("not it"), empty));
    }

    function test_TwoLeafTreeIsOrderIndependent() public {
        bytes32[] memory leaves = _leaves(8, 2);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 2);

        bytes32[] memory proofFor0 = new bytes32[](1);
        proofFor0[0] = leaves[1];
        bytes32[] memory proofFor1 = new bytes32[](1);
        proofFor1[0] = leaves[0];

        assertTrue(anchors.verifyMemory(AGENT_A, index, leaves[0], proofFor0));
        assertTrue(anchors.verifyMemory(AGENT_A, index, leaves[1], proofFor1));
    }

    /// @dev The empty-tree edge case, and the reason `verifyMemory` short-circuits on it: without
    ///      the guard, `leaf == 0` with an empty proof folds to `0`, which equals the empty root.
    function test_EmptyCommitmentProvesNothing() public {
        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(bytes32(0), 1000, 0);

        bytes32[] memory empty = new bytes32[](0);
        assertFalse(anchors.verifyMemory(AGENT_A, index, bytes32(0), empty), "the zero leaf must not verify");
        assertFalse(anchors.verifyMemory(AGENT_A, index, keccak256("anything"), empty));
    }

    function test_ZeroLeafIsRejectedEvenAgainstANonEmptyTree() public {
        // Construct a tree that genuinely contains the zero word as a leaf, then confirm the
        // contract still refuses to treat it as an admissible memory.
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = bytes32(0);
        leaves[1] = keccak256("sibling");
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        uint256 index = anchors.anchor(root, 1000, 2);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaves[1];
        assertFalse(anchors.verifyMemory(AGENT_A, index, bytes32(0), proof));
    }

    function test_VerifyRevertsOnAnUnknownAnchorIndex() public {
        vm.expectRevert(
            abi.encodeWithSelector(AdmissibilityAnchor.AnchorIndexOutOfRange.selector, AGENT_A, uint256(0), uint256(0))
        );
        anchors.verifyMemory(AGENT_A, 0, keccak256("leaf"), new bytes32[](0));
    }

    function test_VerifyLatestUsesTheNewestRoot() public {
        bytes32[] memory oldLeaves = _leaves(9, 4);
        bytes32[] memory newLeaves = _leaves(10, 4);

        vm.startPrank(AGENT_A);
        anchors.anchor(MerkleBuilder.root(oldLeaves), 1000, 4);
        anchors.anchor(MerkleBuilder.root(newLeaves), 2000, 4);
        vm.stopPrank();

        assertTrue(anchors.verifyLatest(AGENT_A, newLeaves[2], MerkleBuilder.proof(newLeaves, 2)));
        assertFalse(
            anchors.verifyLatest(AGENT_A, oldLeaves[2], MerkleBuilder.proof(oldLeaves, 2)),
            "a memory dropped from the newest commitment must stop verifying"
        );
    }

    function test_VerifyLatestRevertsForASilentAgent() public {
        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NoAnchors.selector, AGENT_B));
        anchors.verifyLatest(AGENT_B, keccak256("leaf"), new bytes32[](0));
    }

    function test_AProofAgainstTheWrongAnchorFails() public {
        bytes32[] memory leavesV1 = _leaves(11, 4);
        bytes32[] memory leavesV2 = _leaves(12, 4);

        vm.startPrank(AGENT_A);
        anchors.anchor(MerkleBuilder.root(leavesV1), 1000, 4);
        anchors.anchor(MerkleBuilder.root(leavesV2), 2000, 4);
        vm.stopPrank();

        assertTrue(anchors.verifyMemory(AGENT_A, 0, leavesV1[1], MerkleBuilder.proof(leavesV1, 1)));
        assertFalse(anchors.verifyMemory(AGENT_A, 1, leavesV1[1], MerkleBuilder.proof(leavesV1, 1)));
    }

    function testFuzz_InclusionAndItsNegativeControls(uint256 seed, uint8 rawCount, uint16 rawIndex) public {
        uint256 count = bound(rawCount, 1, 24);
        uint256 index = bound(rawIndex, 0, count - 1);

        bytes32[] memory leaves = _leaves(seed, count);
        bytes32 root = MerkleBuilder.root(leaves);

        vm.prank(AGENT_A);
        // casting to 'uint32' is safe because `count` is bounded to [1, 24] above
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 anchorIndex = anchors.anchor(root, 1000, uint32(count));

        bytes32[] memory proof = MerkleBuilder.proof(leaves, index);

        assertTrue(anchors.verifyMemory(AGENT_A, anchorIndex, leaves[index], proof), "genuine proof must verify");

        bytes32 outsider = keccak256(abi.encodePacked(keccak256(abi.encode("outsider", seed))));
        assertFalse(anchors.verifyMemory(AGENT_A, anchorIndex, outsider, proof), "foreign leaf must not verify");

        bytes32 mutatedLeaf = bytes32(uint256(leaves[index]) ^ 1);
        assertFalse(anchors.verifyMemory(AGENT_A, anchorIndex, mutatedLeaf, proof), "mutated leaf must not verify");

        if (proof.length != 0) {
            bytes32[] memory corrupted = MerkleBuilder.copy(proof);
            uint256 position = seed % proof.length;
            corrupted[position] = bytes32(uint256(corrupted[position]) ^ 1);
            assertFalse(
                anchors.verifyMemory(AGENT_A, anchorIndex, leaves[index], corrupted), "corrupted proof must not verify"
            );
        }
    }
}

// =========================================================================================
// Point-in-time queries
// =========================================================================================

contract AnchorAtTest is AnchorTestBase {
    function _seedHistory() internal {
        vm.startPrank(AGENT_A);
        anchors.anchor(keccak256("r0"), 1000, 1); // index 0
        anchors.anchor(keccak256("r1"), 2000, 2); // index 1
        anchors.anchor(keccak256("r2"), 3000, 3); // index 2
        vm.stopPrank();
    }

    function test_AnchorAtExactWatermark() public {
        _seedHistory();

        (uint256 index, bytes32 root, uint64 asOf,) = anchors.anchorAt(AGENT_A, 2000);
        assertEq(index, 1);
        assertEq(root, keccak256("r1"));
        assertEq(asOf, 2000);
    }

    function test_AnchorAtBetweenTwoAnchorsReturnsTheEarlierOne() public {
        _seedHistory();

        (uint256 index, bytes32 root, uint64 asOf,) = anchors.anchorAt(AGENT_A, 2500);
        assertEq(index, 1, "at t=2500 the agent still only knew what it anchored at t=2000");
        assertEq(root, keccak256("r1"));
        assertEq(asOf, 2000);
    }

    function test_AnchorAtOneSecondBeforeAnAnchor() public {
        _seedHistory();

        (uint256 index,,,) = anchors.anchorAt(AGENT_A, 1999);
        assertEq(index, 0);
    }

    function test_AnchorAtAfterTheLastAnchorReturnsTheLast() public {
        _seedHistory();

        (uint256 index, bytes32 root,,) = anchors.anchorAt(AGENT_A, type(uint64).max);
        assertEq(index, 2);
        assertEq(root, keccak256("r2"));
    }

    function test_AnchorAtBeforeTheFirstAnchorReverts() public {
        _seedHistory();

        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NoAnchorAsOf.selector, AGENT_A, uint64(999)));
        anchors.anchorAt(AGENT_A, 999);
    }

    function test_AnchorAtForASilentAgentReverts() public {
        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NoAnchorAsOf.selector, AGENT_B, uint64(5000)));
        anchors.anchorAt(AGENT_B, 5000);
    }

    function test_AnchorAtReturnsTheBlockNumberOfTheAnchoringTransaction() public {
        vm.roll(21_000_000);
        vm.prank(AGENT_A);
        anchors.anchor(keccak256("r0"), 1000, 1);

        (,,, uint64 blockNumber) = anchors.anchorAt(AGENT_A, 1500);
        assertEq(blockNumber, 21_000_000);
    }

    function test_AnchorAtWithDuplicateWatermarksReturnsTheLatest() public {
        vm.startPrank(AGENT_A);
        anchors.anchor(keccak256("r0"), 1000, 1);
        anchors.anchor(keccak256("r1"), 1000, 2);
        anchors.anchor(keccak256("r2"), 1000, 3);
        anchors.anchor(keccak256("r3"), 4000, 4);
        vm.stopPrank();

        (uint256 index, bytes32 root,,) = anchors.anchorAt(AGENT_A, 1000);
        assertEq(index, 2, "the last commitment at that watermark is the agent's refined statement");
        assertEq(root, keccak256("r2"));
    }

    function test_AnchorAtOverALongHistory() public {
        uint32 total = 64;
        vm.startPrank(AGENT_A);
        for (uint32 i = 0; i < total; ++i) {
            anchors.anchor(keccak256(abi.encode("root", i)), uint64(1000 + i * 10), i + 1);
        }
        vm.stopPrank();

        // Binary search must land on the same entry a linear scan would.
        for (uint32 i = 0; i < total; ++i) {
            uint64 query = uint64(1000 + i * 10 + 5);
            (uint256 index, bytes32 root,,) = anchors.anchorAt(AGENT_A, query);
            assertEq(index, i);
            assertEq(root, keccak256(abi.encode("root", i)));
        }

        (uint256 firstIndex,,,) = anchors.anchorAt(AGENT_A, 1000);
        assertEq(firstIndex, 0);
    }

    function testFuzz_AnchorAtMatchesALinearScan(uint64 query) public {
        uint32 total = 12;
        vm.startPrank(AGENT_A);
        for (uint32 i = 0; i < total; ++i) {
            anchors.anchor(keccak256(abi.encode("root", i)), uint64(100 + i * 7), i + 1);
        }
        vm.stopPrank();

        // Reference answer: the last index whose watermark is at or before `query`.
        bool found = false;
        uint256 expected = 0;
        for (uint32 i = 0; i < total; ++i) {
            if (uint64(100 + i * 7) <= query) {
                expected = i;
                found = true;
            }
        }

        if (!found) {
            vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NoAnchorAsOf.selector, AGENT_A, query));
            anchors.anchorAt(AGENT_A, query);
        } else {
            (uint256 index,,,) = anchors.anchorAt(AGENT_A, query);
            assertEq(index, expected);
        }
    }
}

// =========================================================================================
// Flag registry mirror
// =========================================================================================

contract FlagRegistryTest is AnchorTestBase {
    bytes32 internal constant ACTOR = keccak256(abi.encodePacked("0x00000000000000000000000000000000deadbeef"));

    function test_FlagStoresTheRecord() public {
        bytes32 evidence = keccak256("evidence bundle v1");

        vm.prank(AGENT_A);
        anchors.flag(ACTOR, evidence, "took payment, delivered nothing");

        (bool flagged, bytes32 evidenceDigest, uint64 flaggedAt, string memory reason) =
            anchors.isFlagged(AGENT_A, ACTOR);

        assertTrue(flagged);
        assertEq(evidenceDigest, evidence);
        assertEq(flaggedAt, 1_700_000_000);
        assertEq(reason, "took payment, delivered nothing");
    }

    function test_FlagEmitsActorFlagged() public {
        bytes32 evidence = keccak256("evidence bundle v1");

        vm.expectEmit(true, true, true, true, address(anchors));
        emit AdmissibilityAnchor.ActorFlagged(AGENT_A, ACTOR, evidence, 1_700_000_000, true, "bad delivery");

        vm.prank(AGENT_A);
        anchors.flag(ACTOR, evidence, "bad delivery");
    }

    function test_FlagRequiresEvidence() public {
        vm.prank(AGENT_A);
        vm.expectRevert(AdmissibilityAnchor.EvidenceRequired.selector);
        anchors.flag(ACTOR, bytes32(0), "vibes");
    }

    function test_UnknownActorIsNotFlagged() public view {
        (bool flagged, bytes32 evidenceDigest, uint64 flaggedAt, string memory reason) =
            anchors.isFlagged(AGENT_A, keccak256("stranger"));

        assertFalse(flagged);
        assertEq(evidenceDigest, bytes32(0));
        assertEq(flaggedAt, 0);
        assertEq(reason, "");
    }

    function test_ReflagUpdatesEvidenceButPreservesWhenSuspicionBegan() public {
        vm.prank(AGENT_A);
        anchors.flag(ACTOR, keccak256("evidence v1"), "late delivery");

        vm.warp(1_700_050_000);

        vm.expectEmit(true, true, true, true, address(anchors));
        emit AdmissibilityAnchor.ActorFlagged(
            AGENT_A, ACTOR, keccak256("evidence v2"), 1_700_000_000, false, "outright fraud"
        );

        vm.prank(AGENT_A);
        anchors.flag(ACTOR, keccak256("evidence v2"), "outright fraud");

        (bool flagged, bytes32 evidenceDigest, uint64 flaggedAt, string memory reason) =
            anchors.isFlagged(AGENT_A, ACTOR);
        assertTrue(flagged);
        assertEq(evidenceDigest, keccak256("evidence v2"));
        assertEq(flaggedAt, 1_700_000_000, "the original flag time must survive a re-flag");
        assertEq(reason, "outright fraud");
    }

    function test_UnflagMarksInactiveAndKeepsTheHistory() public {
        vm.prank(AGENT_A);
        anchors.flag(ACTOR, keccak256("evidence v1"), "suspected fraud");

        vm.warp(1_700_100_000);

        vm.expectEmit(true, true, true, true, address(anchors));
        emit AdmissibilityAnchor.ActorUnflagged(AGENT_A, ACTOR, 1_700_100_000, "counterparty produced a valid receipt");

        vm.prank(AGENT_A);
        anchors.unflag(ACTOR, "counterparty produced a valid receipt");

        (bool flagged,,,) = anchors.isFlagged(AGENT_A, ACTOR);
        assertFalse(flagged);

        AdmissibilityAnchor.Flag memory record = anchors.flagRecord(AGENT_A, ACTOR);
        assertFalse(record.active);
        assertEq(record.evidenceDigest, keccak256("evidence v1"), "the evidence pointer survives the retraction");
        assertEq(record.flaggedAt, 1_700_000_000);
        assertEq(record.unflaggedAt, 1_700_100_000);
        assertEq(record.reason, "suspected fraud");
        assertEq(record.clearedReason, "counterparty produced a valid receipt");
    }

    function test_UnflagRevertsWhenNotFlagged() public {
        vm.prank(AGENT_A);
        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NotFlagged.selector, AGENT_A, ACTOR));
        anchors.unflag(ACTOR, "never flagged in the first place");
    }

    function test_UnflagTwiceReverts() public {
        vm.startPrank(AGENT_A);
        anchors.flag(ACTOR, keccak256("evidence"), "fraud");
        anchors.unflag(ACTOR, "cleared");

        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NotFlagged.selector, AGENT_A, ACTOR));
        anchors.unflag(ACTOR, "cleared again");
        vm.stopPrank();
    }

    function test_ReflagAfterUnflagStartsAFreshSuspicion() public {
        vm.prank(AGENT_A);
        anchors.flag(ACTOR, keccak256("evidence v1"), "fraud");

        vm.warp(1_700_100_000);
        vm.prank(AGENT_A);
        anchors.unflag(ACTOR, "cleared");

        vm.warp(1_700_200_000);
        vm.prank(AGENT_A);
        anchors.flag(ACTOR, keccak256("evidence v3"), "relapsed");

        AdmissibilityAnchor.Flag memory record = anchors.flagRecord(AGENT_A, ACTOR);
        assertTrue(record.active);
        assertEq(record.flaggedAt, 1_700_200_000, "a re-raised flag is dated from the new suspicion");
        assertEq(record.unflaggedAt, 0);
        assertEq(record.reason, "relapsed");
        assertEq(record.clearedReason, "", "the stale clearance note must not linger on an active flag");
    }
}

// =========================================================================================
// Per-agent isolation
// =========================================================================================

contract IsolationTest is AnchorTestBase {
    bytes32 internal constant ACTOR = keccak256(abi.encodePacked("acme-agent"));

    function test_AnchorsAreNamespacedToTheCaller() public {
        vm.prank(AGENT_A);
        anchors.anchor(keccak256("a-root"), 1000, 1);

        vm.prank(AGENT_B);
        anchors.anchor(keccak256("b-root"), 5000, 9);

        assertEq(anchors.anchorCount(AGENT_A), 1);
        assertEq(anchors.anchorCount(AGENT_B), 1);
        assertEq(anchors.getAnchor(AGENT_A, 0).root, keccak256("a-root"));
        assertEq(anchors.getAnchor(AGENT_B, 0).root, keccak256("b-root"));
        assertEq(anchors.getAnchor(AGENT_B, 0).agent, AGENT_B);
    }

    /// @dev There is no call path that writes into another agent's history: the only writer is
    ///      `anchor`, and it files under `msg.sender`. B hammering the contract cannot lengthen,
    ///      shorten, or reorder A's log.
    function test_AgentBCannotGrowAgentAHistory() public {
        vm.prank(AGENT_A);
        anchors.anchor(keccak256("a-root"), 1000, 1);

        vm.startPrank(AGENT_B);
        for (uint32 i = 0; i < 5; ++i) {
            anchors.anchor(keccak256(abi.encode("b", i)), uint64(1000 + i), 1);
        }
        vm.stopPrank();

        assertEq(anchors.anchorCount(AGENT_A), 1, "A's history is untouched");
        assertEq(anchors.getAnchor(AGENT_A, 0).root, keccak256("a-root"));
        assertEq(anchors.anchorCount(AGENT_B), 5);
    }

    function test_MonotonicityIsPerAgentNotGlobal() public {
        vm.prank(AGENT_A);
        anchors.anchor(keccak256("a-root"), 9_000_000, 1);

        // B's much older watermark is fine: it is B's first anchor, and B's history is its own.
        vm.prank(AGENT_B);
        anchors.anchor(keccak256("b-root"), 1, 1);

        assertEq(anchors.getAnchor(AGENT_B, 0).asOf, 1);
    }

    function test_AgentBCannotFlagOnBehalfOfAgentA() public {
        vm.prank(AGENT_B);
        anchors.flag(ACTOR, keccak256("b evidence"), "B thinks this actor is bad");

        (bool flaggedByB,,,) = anchors.isFlagged(AGENT_B, ACTOR);
        (bool flaggedByA,,,) = anchors.isFlagged(AGENT_A, ACTOR);

        assertTrue(flaggedByB);
        assertFalse(flaggedByA, "B's opinion must not appear under A's namespace");
    }

    function test_AgentBCannotUnflagAgentAFlag() public {
        vm.prank(AGENT_A);
        anchors.flag(ACTOR, keccak256("a evidence"), "A refuses this actor");

        vm.prank(AGENT_B);
        vm.expectRevert(abi.encodeWithSelector(AdmissibilityAnchor.NotFlagged.selector, AGENT_B, ACTOR));
        anchors.unflag(ACTOR, "B trying to clear someone else's flag");

        (bool stillFlagged,,,) = anchors.isFlagged(AGENT_A, ACTOR);
        assertTrue(stillFlagged, "A's flag survives B's attempt");
    }

    function test_TwoAgentsHoldIndependentOpinions() public {
        vm.prank(AGENT_A);
        anchors.flag(ACTOR, keccak256("a evidence"), "fraud");

        vm.prank(AGENT_B);
        anchors.flag(ACTOR, keccak256("b evidence"), "merely slow");

        (, bytes32 aEvidence,, string memory aReason) = anchors.isFlagged(AGENT_A, ACTOR);
        (, bytes32 bEvidence,, string memory bReason) = anchors.isFlagged(AGENT_B, ACTOR);

        assertEq(aEvidence, keccak256("a evidence"));
        assertEq(bEvidence, keccak256("b evidence"));
        assertEq(aReason, "fraud");
        assertEq(bReason, "merely slow");
    }

    function test_ProofsDoNotCrossAgentBoundaries() public {
        bytes32[] memory leaves = _leaves(42, 4);

        vm.prank(AGENT_A);
        anchors.anchor(MerkleBuilder.root(leaves), 1000, 4);

        vm.prank(AGENT_B);
        anchors.anchor(keccak256("unrelated"), 1000, 1);

        assertTrue(anchors.verifyMemory(AGENT_A, 0, leaves[1], MerkleBuilder.proof(leaves, 1)));
        assertFalse(
            anchors.verifyMemory(AGENT_B, 0, leaves[1], MerkleBuilder.proof(leaves, 1)),
            "A's memory must not verify against B's commitment"
        );
    }
}

// =========================================================================================
// Invariants
// =========================================================================================

/// @dev Drives arbitrary call sequences against the contract from several agent identities.
///      Reverting calls are swallowed so the fuzzer keeps exploring: a rejected anchor is a
///      legitimate outcome, and the point of the invariant is that no accepted sequence of calls,
///      in any order, can leave an agent's watermarks out of order.
contract AnchorHandler is Test {
    AdmissibilityAnchor public immutable ANCHORS;
    address[3] public agents = [address(0xA1), address(0xA2), address(0xA3)];

    uint256 public acceptedAnchors;

    constructor(AdmissibilityAnchor anchorContract) {
        ANCHORS = anchorContract;
    }

    function agentAt(uint256 i) external view returns (address) {
        return agents[i];
    }

    function agentCount() external pure returns (uint256) {
        return 3;
    }

    function doAnchor(uint256 agentSeed, uint64 rawAsOf, uint32 rawLeafCount, bytes32 rawRoot) external {
        address agent = agents[agentSeed % 3];
        // casting is safe because `bound` constrains both values well inside the target widths
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 asOf = uint64(bound(rawAsOf, 0, 10_000));
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 leafCount = uint32(bound(rawLeafCount, 0, 1000));
        bytes32 root = leafCount == 0 ? bytes32(0) : (rawRoot == bytes32(0) ? keccak256("fallback") : rawRoot);

        vm.prank(agent);
        try ANCHORS.anchor(root, asOf, leafCount) {
            ++acceptedAnchors;
        } catch {}
    }

    function doFlag(uint256 agentSeed, bytes32 actorHash, bytes32 evidence) external {
        address agent = agents[agentSeed % 3];
        vm.prank(agent);
        try ANCHORS.flag(actorHash, evidence, "handler") {} catch {}
    }

    function doUnflag(uint256 agentSeed, bytes32 actorHash) external {
        address agent = agents[agentSeed % 3];
        vm.prank(agent);
        try ANCHORS.unflag(actorHash, "handler") {} catch {}
    }
}

contract AdmissibilityAnchorInvariantTest is StdInvariant, Test {
    AdmissibilityAnchor internal anchors;
    AnchorHandler internal handler;

    function setUp() public {
        anchors = new AdmissibilityAnchor();
        handler = new AnchorHandler(anchors);

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = AnchorHandler.doAnchor.selector;
        selectors[1] = AnchorHandler.doFlag.selector;
        selectors[2] = AnchorHandler.doUnflag.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// @dev Guards against the classic silent failure of invariant testing: a handler whose calls
    ///      all revert proves nothing, however green the run looks.
    function afterInvariant() public view {
        assertGt(handler.acceptedAnchors(), 0, "the handler never landed a single anchor");
    }

    /// @notice The core guarantee: whatever sequence of calls anyone makes, an agent's watermarks
    ///         never move backwards, so its published account of what it knew can only be
    ///         extended, never rewritten.
    function invariant_AsOfSequenceIsNonDecreasing() public view {
        for (uint256 a = 0; a < handler.agentCount(); ++a) {
            address agent = handler.agentAt(a);
            uint256 count = anchors.anchorCount(agent);

            uint64 previous = 0;
            for (uint256 i = 0; i < count; ++i) {
                uint64 current = anchors.getAnchor(agent, i).asOf;
                assertGe(current, previous, "asOf regressed inside an agent's history");
                previous = current;
            }
        }
    }

    /// @notice A published anchor is never rewritten, and the point-in-time lookup always resolves
    ///         to a real, correctly-dated entry of the agent's own history.
    function invariant_AnchorAtResolvesConsistently() public view {
        for (uint256 a = 0; a < handler.agentCount(); ++a) {
            address agent = handler.agentAt(a);
            uint256 count = anchors.anchorCount(agent);
            if (count == 0) continue;

            for (uint256 i = 0; i < count; ++i) {
                AdmissibilityAnchor.Anchor memory stored = anchors.getAnchor(agent, i);
                assertEq(stored.agent, agent, "an anchor is always authored by its namespace owner");

                (uint256 index, bytes32 root, uint64 asOf,) = anchors.anchorAt(agent, stored.asOf);
                assertGe(index, i, "the lookup must not resolve to an earlier duplicate");
                assertEq(asOf, stored.asOf, "the resolved anchor must carry the queried watermark");
                assertEq(root, anchors.getAnchor(agent, index).root);

                if (index + 1 < count) {
                    assertGt(
                        anchors.getAnchor(agent, index + 1).asOf,
                        stored.asOf,
                        "the lookup must return the last anchor at that watermark"
                    );
                }
            }
        }
    }
}
