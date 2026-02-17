// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ProofVerifier} from "../src/ProofVerifier.sol";

contract ProofVerifierTest is Test {
    ProofVerifier public verifier;
    address public owner = address(0xE1);
    address public submitter1 = address(0xE2);
    address public outsider = address(0xF1);

    // Pre-compute sha256 hashes to avoid precompile calls consuming vm.prank
    bytes32 public sampleIntent;
    bytes32 public proofDataHash;

    function setUp() public {
        // Pre-compute hashes before any prank calls
        sampleIntent = sha256("intent:transfer-funds");
        proofDataHash = sha256("proof-data");

        vm.prank(owner);
        verifier = new ProofVerifier(owner);

        vm.prank(owner);
        verifier.addSubmitter(submitter1);
    }

    // -------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------

    function test_constructor_setsOwner() public view {
        assertEq(verifier.owner(), owner);
    }

    function test_constructor_ownerIsInitialSubmitter() public view {
        assertTrue(verifier.authorizedSubmitters(owner));
    }

    function test_constructor_revertsOnZeroAddress() public {
        vm.expectRevert(ProofVerifier.ZeroAddress.selector);
        new ProofVerifier(address(0));
    }

    // -------------------------------------------------------------------
    // verifyCommitment
    // -------------------------------------------------------------------

    function test_verifyCommitment_validOpening() public view {
        bytes memory value = "hello world";
        bytes32 blinding = bytes32(uint256(42));
        bytes32 commitment = sha256(abi.encodePacked(value, blinding));

        bool valid = verifier.verifyCommitment(commitment, value, blinding);
        assertTrue(valid);
    }

    function test_verifyCommitment_invalidValue() public view {
        bytes memory value = "hello world";
        bytes32 blinding = bytes32(uint256(42));
        bytes32 commitment = sha256(abi.encodePacked(value, blinding));

        bool valid = verifier.verifyCommitment(commitment, "wrong value", blinding);
        assertFalse(valid);
    }

    function test_verifyCommitment_invalidBlindingFactor() public view {
        bytes memory value = "hello world";
        bytes32 blinding = bytes32(uint256(42));
        bytes32 commitment = sha256(abi.encodePacked(value, blinding));

        bytes32 wrongBlinding = bytes32(uint256(99));
        bool valid = verifier.verifyCommitment(commitment, value, wrongBlinding);
        assertFalse(valid);
    }

    function test_verifyCommitment_emptyValue() public view {
        bytes memory value = "";
        bytes32 blinding = bytes32(uint256(7));
        bytes32 commitment = sha256(abi.encodePacked(value, blinding));

        bool valid = verifier.verifyCommitment(commitment, value, blinding);
        assertTrue(valid);
    }

    // -------------------------------------------------------------------
    // verifyProvenance
    // -------------------------------------------------------------------

    function test_verifyProvenance_validBinding() public view {
        bytes32 promptCommitment = sha256("prompt:do-something");
        bytes32 intentHash = sha256("intent:action");
        uint256 timestamp = 1700000000;
        bytes32 binding = sha256(
            abi.encodePacked(promptCommitment, intentHash, timestamp)
        );

        bool valid = verifier.verifyProvenance(
            promptCommitment, intentHash, binding, timestamp
        );
        assertTrue(valid);
    }

    function test_verifyProvenance_wrongPromptCommitment() public view {
        bytes32 promptCommitment = sha256("prompt:do-something");
        bytes32 intentHash = sha256("intent:action");
        uint256 timestamp = 1700000000;
        bytes32 binding = sha256(
            abi.encodePacked(promptCommitment, intentHash, timestamp)
        );

        bytes32 wrongPrompt = sha256("prompt:wrong");
        bool valid = verifier.verifyProvenance(
            wrongPrompt, intentHash, binding, timestamp
        );
        assertFalse(valid);
    }

    function test_verifyProvenance_wrongIntentHash() public view {
        bytes32 promptCommitment = sha256("prompt:do-something");
        bytes32 intentHash = sha256("intent:action");
        uint256 timestamp = 1700000000;
        bytes32 binding = sha256(
            abi.encodePacked(promptCommitment, intentHash, timestamp)
        );

        bytes32 wrongIntent = sha256("intent:wrong");
        bool valid = verifier.verifyProvenance(
            promptCommitment, wrongIntent, binding, timestamp
        );
        assertFalse(valid);
    }

    function test_verifyProvenance_wrongTimestamp() public view {
        bytes32 promptCommitment = sha256("prompt:do-something");
        bytes32 intentHash = sha256("intent:action");
        uint256 timestamp = 1700000000;
        bytes32 binding = sha256(
            abi.encodePacked(promptCommitment, intentHash, timestamp)
        );

        bool valid = verifier.verifyProvenance(
            promptCommitment, intentHash, binding, 9999999999
        );
        assertFalse(valid);
    }

    // -------------------------------------------------------------------
    // verifyCombinedHash
    // -------------------------------------------------------------------

    function test_verifyCombinedHash_valid() public view {
        bytes32 provHash = sha256("provenance-proof");
        bytes32 nlHash = sha256("non-leakage-proof");
        bytes32 ssHash = sha256("skill-safety-proof");
        bytes32 combined = sha256(
            abi.encodePacked(provHash, nlHash, ssHash)
        );

        bool valid = verifier.verifyCombinedHash(provHash, nlHash, ssHash, combined);
        assertTrue(valid);
    }

    function test_verifyCombinedHash_allZeroInputs() public view {
        bytes32 z = bytes32(0);
        bytes32 combined = sha256(abi.encodePacked(z, z, z));

        bool valid = verifier.verifyCombinedHash(z, z, z, combined);
        assertTrue(valid);
    }

    function test_verifyCombinedHash_wrongHash() public view {
        bytes32 provHash = sha256("provenance-proof");
        bytes32 nlHash = sha256("non-leakage-proof");
        bytes32 ssHash = sha256("skill-safety-proof");

        bytes32 wrongCombined = sha256("totally-wrong");
        bool valid = verifier.verifyCombinedHash(provHash, nlHash, ssHash, wrongCombined);
        assertFalse(valid);
    }

    // -------------------------------------------------------------------
    // recordProof — use startPrank to avoid sha256 precompile consuming prank
    // -------------------------------------------------------------------

    function test_recordProof_ownerCanRecord() public {
        vm.startPrank(owner);
        uint256 id = verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            proofDataHash
        );
        vm.stopPrank();
        assertEq(id, 0);
    }

    function test_recordProof_authorizedSubmitterCanRecord() public {
        vm.startPrank(submitter1);
        uint256 id = verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.NonLeakage,
            true,
            proofDataHash
        );
        vm.stopPrank();
        assertEq(id, 0);
    }

    function test_recordProof_unauthorizedReverts() public {
        vm.startPrank(outsider);
        vm.expectRevert(ProofVerifier.NotAuthorized.selector);
        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            proofDataHash
        );
        vm.stopPrank();
    }

    function test_recordProof_returnsCorrectRecordId() public {
        bytes32 intent0 = sha256("intent-0");
        bytes32 intent1 = sha256("intent-1");
        bytes32 proof0 = sha256("proof-0");
        bytes32 proof1 = sha256("proof-1");

        vm.startPrank(submitter1);

        uint256 id0 = verifier.recordProof(
            intent0,
            ProofVerifier.ProofType.Provenance,
            true,
            proof0
        );
        uint256 id1 = verifier.recordProof(
            intent1,
            ProofVerifier.ProofType.NonLeakage,
            true,
            proof1
        );

        vm.stopPrank();

        assertEq(id0, 0);
        assertEq(id1, 1);
    }

    function test_recordProof_emitsProofVerifiedEvent() public {
        vm.startPrank(submitter1);
        vm.expectEmit(true, true, false, true);
        emit ProofVerifier.ProofVerified(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            submitter1
        );
        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            proofDataHash
        );
        vm.stopPrank();
    }

    function test_recordProof_updatesLatestRecordByIntent() public {
        bytes32 proof1Hash = sha256("proof-1");
        bytes32 proof2Hash = sha256("proof-2");

        vm.startPrank(submitter1);

        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            proof1Hash
        );
        // First record: 1-indexed => 1
        assertEq(verifier.latestRecordByIntent(sampleIntent), 1);

        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.NonLeakage,
            false,
            proof2Hash
        );
        // Second record: 1-indexed => 2
        assertEq(verifier.latestRecordByIntent(sampleIntent), 2);

        vm.stopPrank();
    }

    function test_recordProof_incrementsVerificationCount() public {
        bytes32 i1 = sha256("i1");
        bytes32 i2 = sha256("i2");
        bytes32 i3 = sha256("i3");
        bytes32 p1 = sha256("p1");
        bytes32 p2 = sha256("p2");
        bytes32 p3 = sha256("p3");

        vm.startPrank(submitter1);

        verifier.recordProof(i1, ProofVerifier.ProofType.Provenance, true, p1);
        verifier.recordProof(i2, ProofVerifier.ProofType.Provenance, true, p2);
        verifier.recordProof(i3, ProofVerifier.ProofType.NonLeakage, true, p3);

        vm.stopPrank();

        assertEq(verifier.verificationCount(ProofVerifier.ProofType.Provenance), 2);
        assertEq(verifier.verificationCount(ProofVerifier.ProofType.NonLeakage), 1);
        assertEq(verifier.verificationCount(ProofVerifier.ProofType.SkillSafety), 0);
    }

    // -------------------------------------------------------------------
    // recordProofBatch
    // -------------------------------------------------------------------

    function test_recordProofBatch_recordsMultiple() public {
        bytes32[] memory intents = new bytes32[](3);
        intents[0] = sha256("batch-0");
        intents[1] = sha256("batch-1");
        intents[2] = sha256("batch-2");

        ProofVerifier.ProofType[] memory types = new ProofVerifier.ProofType[](3);
        types[0] = ProofVerifier.ProofType.Provenance;
        types[1] = ProofVerifier.ProofType.NonLeakage;
        types[2] = ProofVerifier.ProofType.SkillSafety;

        bool[] memory flags = new bool[](3);
        flags[0] = true;
        flags[1] = true;
        flags[2] = false;

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = sha256("ph-0");
        hashes[1] = sha256("ph-1");
        hashes[2] = sha256("ph-2");

        vm.startPrank(submitter1);
        verifier.recordProofBatch(intents, types, flags, hashes);
        vm.stopPrank();

        assertEq(verifier.getRecordCount(), 3);
        assertEq(verifier.verificationCount(ProofVerifier.ProofType.Provenance), 1);
        assertEq(verifier.verificationCount(ProofVerifier.ProofType.NonLeakage), 1);
        assertEq(verifier.verificationCount(ProofVerifier.ProofType.SkillSafety), 1);
    }

    function test_recordProofBatch_revertsOnLengthMismatch() public {
        bytes32[] memory intents = new bytes32[](2);
        intents[0] = sha256("a");
        intents[1] = sha256("b");

        ProofVerifier.ProofType[] memory types = new ProofVerifier.ProofType[](1);
        types[0] = ProofVerifier.ProofType.Provenance;

        bool[] memory flags = new bool[](2);
        flags[0] = true;
        flags[1] = true;

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = sha256("h1");
        hashes[1] = sha256("h2");

        vm.startPrank(submitter1);
        vm.expectRevert(ProofVerifier.LengthMismatch.selector);
        verifier.recordProofBatch(intents, types, flags, hashes);
        vm.stopPrank();
    }

    // -------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------

    function test_getRecordCount_increments() public {
        bytes32 intent1 = sha256("i1");
        bytes32 intent2 = sha256("i2");
        bytes32 ph1 = sha256("p1");
        bytes32 ph2 = sha256("p2");

        assertEq(verifier.getRecordCount(), 0);

        vm.startPrank(submitter1);
        verifier.recordProof(intent1, ProofVerifier.ProofType.Provenance, true, ph1);
        assertEq(verifier.getRecordCount(), 1);

        verifier.recordProof(intent2, ProofVerifier.ProofType.NonLeakage, true, ph2);
        assertEq(verifier.getRecordCount(), 2);
        vm.stopPrank();
    }

    function test_getLatestVerification_returnsCorrectRecord() public {
        vm.startPrank(submitter1);
        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            proofDataHash
        );
        vm.stopPrank();

        (bool exists, ProofVerifier.VerificationRecord memory rec) =
            verifier.getLatestVerification(sampleIntent);

        assertTrue(exists);
        assertEq(rec.intentHash, sampleIntent);
        assertTrue(rec.verified);
        assertEq(rec.submitter, submitter1);
        assertEq(uint256(rec.proofType), uint256(ProofVerifier.ProofType.Provenance));
    }

    function test_getLatestVerification_returnsFalseForUnknownIntent() public view {
        bytes32 unknownIntent = sha256("unknown-intent");
        (bool exists,) = verifier.getLatestVerification(unknownIntent);
        assertFalse(exists);
    }

    function test_isVerified_returnsTrueForVerifiedProof() public {
        vm.startPrank(submitter1);
        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            proofDataHash
        );
        vm.stopPrank();

        bool result = verifier.isVerified(sampleIntent, ProofVerifier.ProofType.Provenance);
        assertTrue(result);
    }

    function test_isVerified_returnsFalseForUnverified() public {
        vm.startPrank(submitter1);
        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            false, // not verified
            proofDataHash
        );
        vm.stopPrank();

        bool result = verifier.isVerified(sampleIntent, ProofVerifier.ProofType.Provenance);
        assertFalse(result);
    }

    function test_isVerified_returnsFalseForWrongProofType() public {
        vm.startPrank(submitter1);
        verifier.recordProof(
            sampleIntent,
            ProofVerifier.ProofType.Provenance,
            true,
            proofDataHash
        );
        vm.stopPrank();

        // Ask for NonLeakage but recorded Provenance
        bool result = verifier.isVerified(sampleIntent, ProofVerifier.ProofType.NonLeakage);
        assertFalse(result);
    }

    function test_isVerified_returnsFalseForUnknownIntent() public view {
        bool result = verifier.isVerified(sha256("nope"), ProofVerifier.ProofType.Provenance);
        assertFalse(result);
    }

    // -------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------

    function test_addSubmitter_works() public {
        address newSub = address(0xAA);
        assertFalse(verifier.authorizedSubmitters(newSub));

        vm.prank(owner);
        verifier.addSubmitter(newSub);

        assertTrue(verifier.authorizedSubmitters(newSub));
    }

    function test_addSubmitter_emitsEvent() public {
        address newSub = address(0xBB);

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit ProofVerifier.SubmitterAdded(newSub);
        verifier.addSubmitter(newSub);
    }

    function test_addSubmitter_revertsForNonOwner() public {
        vm.prank(outsider);
        vm.expectRevert(ProofVerifier.NotOwner.selector);
        verifier.addSubmitter(address(0xCC));
    }

    function test_addSubmitter_revertsForDuplicate() public {
        vm.prank(owner);
        vm.expectRevert(ProofVerifier.AlreadySubmitter.selector);
        verifier.addSubmitter(submitter1); // already added in setUp
    }

    function test_addSubmitter_revertsForZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ProofVerifier.ZeroAddress.selector);
        verifier.addSubmitter(address(0));
    }

    function test_removeSubmitter_works() public {
        vm.prank(owner);
        verifier.removeSubmitter(submitter1);

        assertFalse(verifier.authorizedSubmitters(submitter1));

        // Verify they can no longer submit
        vm.startPrank(submitter1);
        vm.expectRevert(ProofVerifier.NotAuthorized.selector);
        verifier.recordProof(sampleIntent, ProofVerifier.ProofType.Provenance, true, proofDataHash);
        vm.stopPrank();
    }

    function test_removeSubmitter_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit ProofVerifier.SubmitterRemoved(submitter1);
        verifier.removeSubmitter(submitter1);
    }

    function test_removeSubmitter_revertsForNonOwner() public {
        vm.prank(outsider);
        vm.expectRevert(ProofVerifier.NotOwner.selector);
        verifier.removeSubmitter(submitter1);
    }

    function test_removeSubmitter_revertsForNonSubmitter() public {
        vm.prank(owner);
        vm.expectRevert(ProofVerifier.NotSubmitter.selector);
        verifier.removeSubmitter(address(0xDD)); // never was a submitter
    }
}
