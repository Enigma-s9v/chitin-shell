// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AgentPolicy.sol";
import "../src/PolicyGovernor.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract PolicyGovernorTest is Test {
    AgentPolicy public policy;
    PolicyGovernor public governor;

    address public gov1 = address(0xB1);
    address public gov2 = address(0xB2);
    address public gov3 = address(0xB3);
    address public outsider = address(0xC1);

    function setUp() public {
        // Deploy AgentPolicy behind proxy
        AgentPolicy impl = new AgentPolicy();
        bytes memory initData = abi.encodeCall(AgentPolicy.initialize, (address(this)));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        policy = AgentPolicy(address(proxy));

        // Deploy governor with 3 governors, requiring 2 approvals
        address[] memory govs = new address[](3);
        govs[0] = gov1;
        govs[1] = gov2;
        govs[2] = gov3;

        governor = new PolicyGovernor(address(policy), govs, 2);

        // Transfer policy ownership to governor
        policy.transferOwnership(address(governor));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _proposeMapAction() internal returns (bytes32) {
        bytes memory callData = abi.encodeCall(
            AgentPolicy.mapAction, ("read_file", 0)
        );
        vm.prank(gov1);
        return governor.propose(callData, "Map read_file to tier 0");
    }

    // -----------------------------------------------------------------------
    // Proposal Creation
    // -----------------------------------------------------------------------

    function test_propose_createsProposal() public {
        bytes32 id = _proposeMapAction();

        PolicyGovernor.ProposalCore memory p = governor.getProposal(id);
        assertEq(p.proposer, gov1);
        assertEq(p.approvals, 1); // proposer auto-approves
        assertFalse(p.executed);
        assertFalse(p.cancelled);
        assertTrue(p.executesAt > block.timestamp);
    }

    function test_propose_emitsEvent() public {
        bytes memory callData = abi.encodeCall(AgentPolicy.mapAction, ("test", 1));

        vm.prank(gov1);
        vm.expectEmit(false, true, false, true);
        emit PolicyGovernor.ProposalCreated(bytes32(0), gov1, "Test proposal");
        // Note: we can't predict the exact id, so we just check indexed params
        governor.propose(callData, "Test proposal");
    }

    function test_propose_onlyGovernor() public {
        bytes memory callData = abi.encodeCall(AgentPolicy.mapAction, ("hack", 0));

        vm.prank(outsider);
        vm.expectRevert(PolicyGovernor.NotGovernor.selector);
        governor.propose(callData, "Hack");
    }

    // -----------------------------------------------------------------------
    // Approval
    // -----------------------------------------------------------------------

    function test_approve_incrementsCount() public {
        bytes32 id = _proposeMapAction();

        vm.prank(gov2);
        governor.approve(id);

        PolicyGovernor.ProposalCore memory p = governor.getProposal(id);
        assertEq(p.approvals, 2);
    }

    function test_approve_doubleApprovalRejected() public {
        bytes32 id = _proposeMapAction();

        vm.prank(gov1); // gov1 already approved (auto)
        vm.expectRevert(PolicyGovernor.AlreadyApproved.selector);
        governor.approve(id);
    }

    function test_approve_emitsEvent() public {
        bytes32 id = _proposeMapAction();

        vm.prank(gov2);
        vm.expectEmit(true, true, false, true);
        emit PolicyGovernor.ProposalApproved(id, gov2, 2);
        governor.approve(id);
    }

    // -----------------------------------------------------------------------
    // Execution
    // -----------------------------------------------------------------------

    function test_execute_afterTimelockAndApprovals() public {
        bytes32 id = _proposeMapAction();

        // Second approval
        vm.prank(gov2);
        governor.approve(id);

        // Warp past timelock
        vm.warp(block.timestamp + 24 hours + 1);

        // Execute
        vm.prank(gov1);
        governor.execute(id);

        // Verify the action was mapped on AgentPolicy
        assertEq(policy.getActionTier("read_file"), 0);

        // Proposal marked executed
        PolicyGovernor.ProposalCore memory p = governor.getProposal(id);
        assertTrue(p.executed);
    }

    function test_execute_revertsBeforeTimelock() public {
        bytes32 id = _proposeMapAction();

        vm.prank(gov2);
        governor.approve(id);

        // Don't warp — still within timelock
        vm.prank(gov1);
        vm.expectRevert(PolicyGovernor.TimelockNotElapsed.selector);
        governor.execute(id);
    }

    function test_execute_revertsWithoutEnoughApprovals() public {
        bytes32 id = _proposeMapAction();
        // Only 1 approval (proposer), need 2

        vm.warp(block.timestamp + 24 hours + 1);

        vm.prank(gov1);
        vm.expectRevert(PolicyGovernor.InsufficientApprovals.selector);
        governor.execute(id);
    }

    function test_execute_emitsEvent() public {
        bytes32 id = _proposeMapAction();
        vm.prank(gov2);
        governor.approve(id);
        vm.warp(block.timestamp + 24 hours + 1);

        vm.prank(gov3);
        vm.expectEmit(true, true, false, true);
        emit PolicyGovernor.ProposalExecuted(id, gov3);
        governor.execute(id);
    }

    // -----------------------------------------------------------------------
    // Cancellation
    // -----------------------------------------------------------------------

    function test_cancel_setsFlag() public {
        bytes32 id = _proposeMapAction();

        vm.prank(gov1);
        governor.cancel(id);

        PolicyGovernor.ProposalCore memory p = governor.getProposal(id);
        assertTrue(p.cancelled);
    }

    function test_cancel_preventsExecution() public {
        bytes32 id = _proposeMapAction();
        vm.prank(gov2);
        governor.approve(id);
        vm.warp(block.timestamp + 24 hours + 1);

        // Cancel
        vm.prank(gov1);
        governor.cancel(id);

        // Try execute
        vm.prank(gov1);
        vm.expectRevert(PolicyGovernor.AlreadyCancelled.selector);
        governor.execute(id);
    }

    // -----------------------------------------------------------------------
    // Governor Management
    // -----------------------------------------------------------------------

    function test_addGovernor_viaSelfCall() public {
        address newGov = address(0xD1);

        // Propose adding governor (callData targets PolicyGovernor itself)
        bytes memory callData = abi.encodeCall(PolicyGovernor.addGovernor, (newGov));

        // For addGovernor, the call must come from the governor contract itself
        // So we propose a call that the governor makes to itself
        // We need to encode the call differently — the target is the governor, not policy
        // Actually, execute() calls policy. For self-calls we need a different approach.
        // Let's test the direct path
        vm.prank(address(governor));
        governor.addGovernor(newGov);

        assertTrue(governor.isGovernor(newGov));
        assertEq(governor.governorCount(), 4);
    }

    function test_addGovernor_revertsIfNotSelf() public {
        vm.prank(gov1);
        vm.expectRevert(PolicyGovernor.OnlySelf.selector);
        governor.addGovernor(address(0xD2));
    }

    function test_removeGovernor_viaSelfCall() public {
        vm.prank(address(governor));
        governor.removeGovernor(gov3);

        assertFalse(governor.isGovernor(gov3));
        assertEq(governor.governorCount(), 2);
    }

    function test_removeGovernor_cannotRemoveBelowThreshold() public {
        // Remove gov3 first (3→2 governors, threshold=2)
        vm.prank(address(governor));
        governor.removeGovernor(gov3);

        // Now removing gov2 would leave 1 governor < 2 required
        vm.prank(address(governor));
        vm.expectRevert(PolicyGovernor.CannotRemoveLastGovernor.selector);
        governor.removeGovernor(gov2);
    }

    // -----------------------------------------------------------------------
    // Constructor Validation
    // -----------------------------------------------------------------------

    function test_constructor_revertsZeroPolicy() public {
        address[] memory govs = new address[](1);
        govs[0] = gov1;

        vm.expectRevert(PolicyGovernor.ZeroAddress.selector);
        new PolicyGovernor(address(0), govs, 1);
    }

    function test_constructor_revertsInvalidThreshold() public {
        address[] memory govs = new address[](2);
        govs[0] = gov1;
        govs[1] = gov2;

        // required > governors.length
        vm.expectRevert(PolicyGovernor.InvalidThreshold.selector);
        new PolicyGovernor(address(policy), govs, 3);
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    function test_proposalCount_incrementsCorrectly() public {
        assertEq(governor.proposalCount(), 0);

        _proposeMapAction();
        assertEq(governor.proposalCount(), 1);

        bytes memory callData2 = abi.encodeCall(AgentPolicy.mapAction, ("write_file", 1));
        vm.prank(gov2);
        governor.propose(callData2, "Map write_file");
        assertEq(governor.proposalCount(), 2);
    }

    function test_hasApproved_tracksCorrectly() public {
        bytes32 id = _proposeMapAction();

        assertTrue(governor.hasApproved(id, gov1));
        assertFalse(governor.hasApproved(id, gov2));

        vm.prank(gov2);
        governor.approve(id);
        assertTrue(governor.hasApproved(id, gov2));
    }
}
