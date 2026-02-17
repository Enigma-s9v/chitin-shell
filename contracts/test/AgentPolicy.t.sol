// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AgentPolicy.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract AgentPolicyTest is Test {
    AgentPolicy public policy;
    AgentPolicy public impl;
    address public owner = address(0xA1);
    address public alice = address(0xA2);
    address public bob = address(0xA3);

    function setUp() public {
        impl = new AgentPolicy();
        bytes memory initData = abi.encodeCall(AgentPolicy.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        policy = AgentPolicy(address(proxy));
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    function test_initialize_setsOwner() public view {
        assertEq(policy.owner(), owner);
    }

    function test_initialize_setsPolicyVersionTo1() public view {
        assertEq(policy.policyVersion(), 1);
    }

    function test_initialize_cannotReinitialize() public {
        vm.expectRevert();
        policy.initialize(alice);
    }

    // -----------------------------------------------------------------------
    // Tier Config
    // -----------------------------------------------------------------------

    function test_setTierConfig_storesCorrectly() public {
        string[] memory actions = new string[](2);
        actions[0] = "read_file";
        actions[1] = "list_dir";

        vm.prank(owner);
        policy.setTierConfig(0, "Read-only ops", actions, 0, 100, 3600);

        (string memory desc, uint8 verification, uint32 rlMax, uint32 rlWindow) =
            policy.getTierConfig(0);

        assertEq(desc, "Read-only ops");
        assertEq(verification, 0);
        assertEq(rlMax, 100);
        assertEq(rlWindow, 3600);

        string[] memory stored = policy.getTierActions(0);
        assertEq(stored.length, 2);
        assertEq(stored[0], "read_file");
        assertEq(stored[1], "list_dir");
    }

    function test_setTierConfig_incrementsVersion() public {
        uint256 before = policy.policyVersion();
        string[] memory actions = new string[](0);

        vm.prank(owner);
        policy.setTierConfig(1, "Tier 1", actions, 1, 50, 60);

        assertEq(policy.policyVersion(), before + 1);
    }

    function test_setTierConfig_revertsInvalidVerification() public {
        string[] memory actions = new string[](0);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AgentPolicy.InvalidVerificationLevel.selector, 5));
        policy.setTierConfig(0, "Bad", actions, 5, 0, 0);
    }

    function test_setTierConfig_emitsEvents() public {
        string[] memory actions = new string[](1);
        actions[0] = "test_action";

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit AgentPolicy.TierConfigSet(2, "Tier 2", 2);
        policy.setTierConfig(2, "Tier 2", actions, 2, 10, 300);
    }

    // -----------------------------------------------------------------------
    // Action Mapping
    // -----------------------------------------------------------------------

    function test_mapAction_setsActionTier() public {
        vm.prank(owner);
        policy.mapAction("send_email", 1);

        assertEq(policy.getActionTier("send_email"), 1);
    }

    function test_mapActions_batchSetsMultiple() public {
        string[] memory actions = new string[](3);
        actions[0] = "transfer_funds";
        actions[1] = "deploy_contract";
        actions[2] = "delete_data";

        vm.prank(owner);
        policy.mapActions(actions, 2);

        assertEq(policy.getActionTier("transfer_funds"), 2);
        assertEq(policy.getActionTier("deploy_contract"), 2);
        assertEq(policy.getActionTier("delete_data"), 2);
    }

    function test_mapAction_emitsActionMapped() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit AgentPolicy.ActionMapped("ping", 0);
        policy.mapAction("ping", 0);
    }

    // -----------------------------------------------------------------------
    // Verify Action
    // -----------------------------------------------------------------------

    function test_verifyAction_tier0AutoApproves() public {
        vm.prank(owner);
        policy.mapAction("read_file", 0);

        (bool approved, uint8 tier, string memory reason) =
            policy.verifyAction("did:chitin:agent1", "read_file", bytes32(uint256(1)));

        assertTrue(approved);
        assertEq(tier, 0);
        assertEq(reason, "approved");
    }

    function test_verifyAction_tier3RequiresHumanApproval() public {
        vm.prank(owner);
        policy.mapAction("nuke_server", 3);

        (bool approved, uint8 tier, string memory reason) =
            policy.verifyAction("did:chitin:agent1", "nuke_server", bytes32(uint256(2)));

        assertFalse(approved);
        assertEq(tier, 3);
        assertEq(reason, "human_approval_required");
    }

    function test_verifyAction_unknownActionDefaultsTier3() public {
        (bool approved, uint8 tier, string memory reason) =
            policy.verifyAction("did:chitin:agent1", "totally_unknown", bytes32(uint256(3)));

        assertFalse(approved);
        assertEq(tier, 3);
        assertEq(reason, "human_approval_required");
    }

    function test_verifyAction_blacklistedActionRejected() public {
        vm.prank(owner);
        policy.mapAction("read_file", 0);

        vm.prank(owner);
        policy.setActionBlacklist("read_file", true);

        (bool approved,, string memory reason) =
            policy.verifyAction("did:chitin:agent1", "read_file", bytes32(uint256(4)));

        assertFalse(approved);
        assertEq(reason, "action_blacklisted");
    }

    function test_verifyAction_emitsActionVerifiedEvent() public {
        vm.prank(owner);
        policy.mapAction("read_file", 0);

        bytes32 intentHash = bytes32(uint256(99));
        vm.expectEmit(true, false, false, true);
        emit AgentPolicy.ActionVerified(intentHash, "read_file", 0, true, "approved");

        policy.verifyAction("did:chitin:agent1", "read_file", intentHash);
    }

    // -----------------------------------------------------------------------
    // Rate Limiting
    // -----------------------------------------------------------------------

    function test_rateLimit_blocksExcessRequests() public {
        string[] memory actions = new string[](1);
        actions[0] = "api_call";

        vm.prank(owner);
        policy.setTierConfig(1, "Rate limited", actions, 1, 2, 3600); // max 2 per hour

        // First two should succeed
        (bool ok1,,) = policy.verifyAction("did:chitin:agent1", "api_call", bytes32(uint256(10)));
        assertTrue(ok1);
        (bool ok2,,) = policy.verifyAction("did:chitin:agent1", "api_call", bytes32(uint256(11)));
        assertTrue(ok2);

        // Third should be rate-limited
        (bool ok3,, string memory reason) =
            policy.verifyAction("did:chitin:agent1", "api_call", bytes32(uint256(12)));
        assertFalse(ok3);
        assertEq(reason, "rate_limit_exceeded");
    }

    function test_rateLimit_allowsAfterWindowExpires() public {
        string[] memory actions = new string[](1);
        actions[0] = "api_call";

        vm.prank(owner);
        policy.setTierConfig(1, "Rate limited", actions, 1, 1, 60); // max 1 per 60s

        // First call succeeds
        (bool ok1,,) = policy.verifyAction("did:chitin:agent1", "api_call", bytes32(uint256(20)));
        assertTrue(ok1);

        // Second call should fail
        (bool ok2,,) = policy.verifyAction("did:chitin:agent1", "api_call", bytes32(uint256(21)));
        assertFalse(ok2);

        // Warp past window
        vm.warp(block.timestamp + 61);

        // Should succeed again
        (bool ok3,,) = policy.verifyAction("did:chitin:agent1", "api_call", bytes32(uint256(22)));
        assertTrue(ok3);
    }

    function test_checkRateLimit_returnsRemaining() public {
        string[] memory actions = new string[](1);
        actions[0] = "api_call";

        vm.prank(owner);
        policy.setTierConfig(1, "Rate limited", actions, 1, 3, 3600);

        // Before any calls
        (bool allowed, uint256 remaining) = policy.checkRateLimit("did:chitin:agent1", "api_call");
        assertTrue(allowed);
        assertEq(remaining, 3);

        // After one call
        policy.verifyAction("did:chitin:agent1", "api_call", bytes32(uint256(30)));

        (allowed, remaining) = policy.checkRateLimit("did:chitin:agent1", "api_call");
        assertTrue(allowed);
        assertEq(remaining, 2);
    }

    // -----------------------------------------------------------------------
    // Whitelist / Blacklist
    // -----------------------------------------------------------------------

    function test_setAgentWhitelist_toggles() public {
        assertFalse(policy.whitelistedAgents(alice));

        vm.prank(owner);
        policy.setAgentWhitelist(alice, true);
        assertTrue(policy.whitelistedAgents(alice));

        vm.prank(owner);
        policy.setAgentWhitelist(alice, false);
        assertFalse(policy.whitelistedAgents(alice));
    }

    function test_setActionBlacklist_toggles() public {
        bytes32 h = keccak256(bytes("dangerous_op"));
        assertFalse(policy.blacklistedActions(h));

        vm.prank(owner);
        policy.setActionBlacklist("dangerous_op", true);
        assertTrue(policy.blacklistedActions(h));

        vm.prank(owner);
        policy.setActionBlacklist("dangerous_op", false);
        assertFalse(policy.blacklistedActions(h));
    }

    function test_setAgentWhitelist_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit AgentPolicy.AgentWhitelisted(alice, true);
        policy.setAgentWhitelist(alice, true);
    }

    // -----------------------------------------------------------------------
    // Access Control
    // -----------------------------------------------------------------------

    function test_onlyOwner_setTierConfig() public {
        string[] memory actions = new string[](0);

        vm.prank(alice);
        vm.expectRevert();
        policy.setTierConfig(0, "Hack", actions, 0, 0, 0);
    }

    function test_onlyOwner_mapAction() public {
        vm.prank(alice);
        vm.expectRevert();
        policy.mapAction("hack", 0);
    }

    function test_onlyOwner_setWhitelist() public {
        vm.prank(alice);
        vm.expectRevert();
        policy.setAgentWhitelist(bob, true);
    }

    function test_onlyOwner_setBlacklist() public {
        vm.prank(alice);
        vm.expectRevert();
        policy.setActionBlacklist("hack", true);
    }

    // -----------------------------------------------------------------------
    // UUPS Upgrade
    // -----------------------------------------------------------------------

    function test_uups_upgradeWorks() public {
        AgentPolicy newImpl = new AgentPolicy();

        vm.prank(owner);
        policy.upgradeToAndCall(address(newImpl), "");

        // Policy still works after upgrade
        assertEq(policy.owner(), owner);
    }

    function test_uups_nonOwnerCannotUpgrade() public {
        AgentPolicy newImpl = new AgentPolicy();

        vm.prank(alice);
        vm.expectRevert();
        policy.upgradeToAndCall(address(newImpl), "");
    }

    // -----------------------------------------------------------------------
    // Policy Version
    // -----------------------------------------------------------------------

    function test_policyVersion_incrementsOnMultipleUpdates() public {
        assertEq(policy.policyVersion(), 1);

        vm.startPrank(owner);
        policy.mapAction("a", 0);
        assertEq(policy.policyVersion(), 2);

        policy.mapAction("b", 1);
        assertEq(policy.policyVersion(), 3);

        string[] memory actions = new string[](1);
        actions[0] = "c";
        policy.mapActions(actions, 2);
        assertEq(policy.policyVersion(), 4);
        vm.stopPrank();
    }
}
