// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AuditLog.sol";

contract AuditLogTest is Test {
    AuditLog public auditLog;
    address public owner = address(0xE1);
    address public submitter1 = address(0xE2);
    address public submitter2 = address(0xE3);
    address public outsider = address(0xF1);

    bytes32 public agentDid1 = keccak256("did:chitin:agent-alpha");
    bytes32 public agentDid2 = keccak256("did:chitin:agent-beta");

    function setUp() public {
        vm.prank(owner);
        auditLog = new AuditLog(owner);

        vm.prank(owner);
        auditLog.addSubmitter(submitter1);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// @dev Build a simple 4-leaf Merkle tree and return root + proof for leaf at index 0
    function _buildMerkleTree()
        internal
        pure
        returns (bytes32 root, bytes32 leaf, bytes32[] memory proof)
    {
        bytes32 leaf0 = keccak256("entry0");
        bytes32 leaf1 = keccak256("entry1");
        bytes32 leaf2 = keccak256("entry2");
        bytes32 leaf3 = keccak256("entry3");

        // Level 1
        bytes32 node01 = keccak256(abi.encodePacked(leaf0, leaf1));
        bytes32 node23 = keccak256(abi.encodePacked(leaf2, leaf3));

        // Root
        root = keccak256(abi.encodePacked(node01, node23));

        // Proof for leaf0 (index 0): [leaf1, node23]
        leaf = leaf0;
        proof = new bytes32[](2);
        proof[0] = leaf1;
        proof[1] = node23;
    }

    // -----------------------------------------------------------------------
    // Anchor Commitment
    // -----------------------------------------------------------------------

    function test_anchorCommitment_storesCorrectly() public {
        bytes32 root = keccak256("root1");

        vm.prank(submitter1);
        uint256 id = auditLog.anchorCommitment(root, 100, 1000, 2000, agentDid1);

        assertEq(id, 0);

        AuditLog.Commitment memory c = auditLog.getCommitment(0);
        assertEq(c.merkleRoot, root);
        assertEq(c.entryCount, 100);
        assertEq(c.fromTimestamp, 1000);
        assertEq(c.toTimestamp, 2000);
        assertEq(c.submitter, submitter1);
        assertEq(c.blockNumber, block.number);
    }

    function test_anchorCommitment_emitsEvent() public {
        bytes32 root = keccak256("root2");

        vm.prank(submitter1);
        vm.expectEmit(true, true, false, true);
        emit AuditLog.CommitmentAnchored(0, root, 50, 1000, 2000, submitter1);
        auditLog.anchorCommitment(root, 50, 1000, 2000, agentDid1);
    }

    function test_anchorCommitment_ownerCanAlsoSubmit() public {
        bytes32 root = keccak256("root_owner");

        vm.prank(owner);
        uint256 id = auditLog.anchorCommitment(root, 10, 100, 200, agentDid1);
        assertEq(id, 0);
    }

    function test_anchorCommitment_revertsUnauthorized() public {
        vm.prank(outsider);
        vm.expectRevert(AuditLog.NotAuthorized.selector);
        auditLog.anchorCommitment(bytes32(0), 1, 1, 2, agentDid1);
    }

    function test_anchorCommitment_revertsInvalidTimeRange() public {
        vm.prank(submitter1);
        vm.expectRevert(AuditLog.InvalidTimeRange.selector);
        auditLog.anchorCommitment(keccak256("root"), 1, 2000, 1000, agentDid1);
    }

    // -----------------------------------------------------------------------
    // Merkle Verification
    // -----------------------------------------------------------------------

    function test_verifyInclusion_validProof() public {
        (bytes32 root, bytes32 leaf, bytes32[] memory proof) = _buildMerkleTree();

        vm.prank(submitter1);
        auditLog.anchorCommitment(root, 4, 1000, 2000, agentDid1);

        bool valid = auditLog.verifyInclusion(0, leaf, proof, 0);
        assertTrue(valid);
    }

    function test_verifyInclusion_rejectsInvalidProof() public {
        (bytes32 root,, bytes32[] memory proof) = _buildMerkleTree();

        vm.prank(submitter1);
        auditLog.anchorCommitment(root, 4, 1000, 2000, agentDid1);

        // Use wrong leaf
        bytes32 wrongLeaf = keccak256("wrong_entry");
        bool valid = auditLog.verifyInclusion(0, wrongLeaf, proof, 0);
        assertFalse(valid);
    }

    function test_verifyInclusion_rejectsWrongIndex() public {
        (bytes32 root, bytes32 leaf, bytes32[] memory proof) = _buildMerkleTree();

        vm.prank(submitter1);
        auditLog.anchorCommitment(root, 4, 1000, 2000, agentDid1);

        // Wrong index (1 instead of 0)
        bool valid = auditLog.verifyInclusion(0, leaf, proof, 1);
        assertFalse(valid);
    }

    function test_verifyInclusion_revertsInvalidCommitmentId() public {
        bytes32[] memory proof = new bytes32[](0);

        vm.expectRevert(AuditLog.InvalidCommitmentId.selector);
        auditLog.verifyInclusion(999, bytes32(0), proof, 0);
    }

    function test_verifyInclusion_emptyProofSingleLeaf() public {
        // Single-leaf tree: root == leaf
        bytes32 leaf = keccak256("only_entry");
        bytes32[] memory proof = new bytes32[](0);

        vm.prank(submitter1);
        auditLog.anchorCommitment(leaf, 1, 100, 100, agentDid1);

        bool valid = auditLog.verifyInclusion(0, leaf, proof, 0);
        assertTrue(valid);
    }

    // -----------------------------------------------------------------------
    // Agent Tracking
    // -----------------------------------------------------------------------

    function test_latestCommitmentByAgent_tracks() public {
        bytes32 root1 = keccak256("root_a1");
        bytes32 root2 = keccak256("root_a2");

        vm.startPrank(submitter1);
        auditLog.anchorCommitment(root1, 10, 1000, 2000, agentDid1);
        auditLog.anchorCommitment(root2, 20, 2001, 3000, agentDid1);
        vm.stopPrank();

        AuditLog.Commitment memory latest = auditLog.getLatestByAgent(agentDid1);
        assertEq(latest.merkleRoot, root2);
        assertEq(latest.entryCount, 20);
    }

    function test_getLatestByAgent_revertsNoCommitment() public {
        vm.expectRevert(AuditLog.NoCommitmentForAgent.selector);
        auditLog.getLatestByAgent(keccak256("did:chitin:nonexistent"));
    }

    // -----------------------------------------------------------------------
    // Commitment Count
    // -----------------------------------------------------------------------

    function test_getCommitmentCount_incrementsCorrectly() public {
        assertEq(auditLog.getCommitmentCount(), 0);

        vm.startPrank(submitter1);
        auditLog.anchorCommitment(keccak256("r1"), 1, 1, 1, agentDid1);
        assertEq(auditLog.getCommitmentCount(), 1);

        auditLog.anchorCommitment(keccak256("r2"), 2, 2, 2, agentDid2);
        assertEq(auditLog.getCommitmentCount(), 2);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------------
    // Submitter Management
    // -----------------------------------------------------------------------

    function test_addSubmitter_authorizesAddress() public {
        assertFalse(auditLog.authorizedSubmitters(submitter2));

        vm.prank(owner);
        auditLog.addSubmitter(submitter2);

        assertTrue(auditLog.authorizedSubmitters(submitter2));
    }

    function test_addSubmitter_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit AuditLog.SubmitterAdded(submitter2);
        auditLog.addSubmitter(submitter2);
    }

    function test_addSubmitter_revertsIfAlreadySubmitter() public {
        vm.prank(owner);
        vm.expectRevert(AuditLog.AlreadySubmitter.selector);
        auditLog.addSubmitter(submitter1); // already added in setUp
    }

    function test_removeSubmitter_deauthorizes() public {
        vm.prank(owner);
        auditLog.removeSubmitter(submitter1);

        assertFalse(auditLog.authorizedSubmitters(submitter1));

        vm.prank(submitter1);
        vm.expectRevert(AuditLog.NotAuthorized.selector);
        auditLog.anchorCommitment(bytes32(0), 1, 1, 1, agentDid1);
    }

    function test_removeSubmitter_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit AuditLog.SubmitterRemoved(submitter1);
        auditLog.removeSubmitter(submitter1);
    }

    function test_addSubmitter_onlyOwner() public {
        vm.prank(outsider);
        vm.expectRevert(AuditLog.NotOwner.selector);
        auditLog.addSubmitter(outsider);
    }

    function test_removeSubmitter_onlyOwner() public {
        vm.prank(outsider);
        vm.expectRevert(AuditLog.NotOwner.selector);
        auditLog.removeSubmitter(submitter1);
    }

    // -----------------------------------------------------------------------
    // Multiple Commitments
    // -----------------------------------------------------------------------

    function test_multipleCommitments_differentAgents() public {
        vm.startPrank(submitter1);
        auditLog.anchorCommitment(keccak256("r1"), 10, 100, 200, agentDid1);
        auditLog.anchorCommitment(keccak256("r2"), 20, 300, 400, agentDid2);
        auditLog.anchorCommitment(keccak256("r3"), 30, 500, 600, agentDid1);
        vm.stopPrank();

        assertEq(auditLog.getCommitmentCount(), 3);

        // Agent 1's latest is commitment 2 (index 2)
        AuditLog.Commitment memory c1 = auditLog.getLatestByAgent(agentDid1);
        assertEq(c1.entryCount, 30);

        // Agent 2's latest is commitment 1 (index 1)
        AuditLog.Commitment memory c2 = auditLog.getLatestByAgent(agentDid2);
        assertEq(c2.entryCount, 20);
    }

    // -----------------------------------------------------------------------
    // Edge Cases
    // -----------------------------------------------------------------------

    function test_anchorCommitment_sameTimestamps() public {
        // fromTimestamp == toTimestamp is valid (single-second batch)
        vm.prank(submitter1);
        uint256 id = auditLog.anchorCommitment(keccak256("root"), 1, 500, 500, agentDid1);
        assertEq(id, 0);

        AuditLog.Commitment memory c = auditLog.getCommitment(0);
        assertEq(c.fromTimestamp, 500);
        assertEq(c.toTimestamp, 500);
    }

    function test_constructor_revertsZeroOwner() public {
        vm.expectRevert(AuditLog.ZeroAddress.selector);
        new AuditLog(address(0));
    }
}
