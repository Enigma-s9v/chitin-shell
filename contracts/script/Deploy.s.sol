// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/AgentPolicy.sol";
import "../src/PolicyGovernor.sol";
import "../src/AuditLog.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title Deploy
/// @notice Deploys the complete Chitin Shell on-chain policy stack:
///         1. AgentPolicy (UUPS proxy)
///         2. PolicyGovernor (multisig + timelock)
///         3. AuditLog (audit commitment anchoring)
///         Then transfers AgentPolicy ownership to PolicyGovernor and
///         configures default tier policies.
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        // Governor addresses (can be overridden via env vars)
        address gov1 = vm.envOr("GOVERNOR_1", deployer);
        address gov2 = vm.envOr("GOVERNOR_2", deployer);
        uint8 requiredApprovals = uint8(vm.envOr("REQUIRED_APPROVALS", uint256(1)));

        vm.startBroadcast(deployerKey);

        // ---------------------------------------------------------------
        // 1. Deploy AgentPolicy (UUPS Proxy)
        // ---------------------------------------------------------------
        AgentPolicy policyImpl = new AgentPolicy();
        bytes memory initData = abi.encodeCall(AgentPolicy.initialize, (deployer));
        ERC1967Proxy policyProxy = new ERC1967Proxy(address(policyImpl), initData);
        AgentPolicy policy = AgentPolicy(address(policyProxy));

        console.log("AgentPolicy (Impl):", address(policyImpl));
        console.log("AgentPolicy (Proxy):", address(policyProxy));

        // ---------------------------------------------------------------
        // 2. Set up default tier configurations
        // ---------------------------------------------------------------

        // Tier 0: Read-only, auto-approve
        string[] memory tier0Actions = new string[](3);
        tier0Actions[0] = "read_file";
        tier0Actions[1] = "list_directory";
        tier0Actions[2] = "get_status";
        policy.setTierConfig(0, "Read-only operations", tier0Actions, 0, 1000, 3600);

        // Tier 1: Standard operations, local verification
        string[] memory tier1Actions = new string[](3);
        tier1Actions[0] = "write_file";
        tier1Actions[1] = "send_message";
        tier1Actions[2] = "api_call";
        policy.setTierConfig(1, "Standard operations", tier1Actions, 1, 100, 3600);

        // Tier 2: Sensitive operations, on-chain verification
        string[] memory tier2Actions = new string[](3);
        tier2Actions[0] = "transfer_funds";
        tier2Actions[1] = "modify_permissions";
        tier2Actions[2] = "deploy_contract";
        policy.setTierConfig(2, "Sensitive operations", tier2Actions, 2, 10, 3600);

        // Tier 3: Critical operations, human approval (default for unknown)
        string[] memory tier3Actions = new string[](2);
        tier3Actions[0] = "delete_data";
        tier3Actions[1] = "system_admin";
        policy.setTierConfig(3, "Critical operations - human approval required", tier3Actions, 3, 1, 86400);

        console.log("Default tier configs set");

        // ---------------------------------------------------------------
        // 3. Deploy PolicyGovernor
        // ---------------------------------------------------------------
        address[] memory governors = new address[](2);
        governors[0] = gov1;
        governors[1] = gov2;

        PolicyGovernor policyGovernor = new PolicyGovernor(
            address(policyProxy),
            governors,
            requiredApprovals
        );
        console.log("PolicyGovernor:", address(policyGovernor));

        // ---------------------------------------------------------------
        // 4. Deploy AuditLog
        // ---------------------------------------------------------------
        AuditLog auditLog = new AuditLog(deployer);
        console.log("AuditLog:", address(auditLog));

        // Authorize deployer as initial submitter
        auditLog.addSubmitter(deployer);

        // ---------------------------------------------------------------
        // 5. Transfer AgentPolicy ownership to PolicyGovernor
        // ---------------------------------------------------------------
        policy.transferOwnership(address(policyGovernor));
        console.log("AgentPolicy ownership transferred to PolicyGovernor");

        vm.stopBroadcast();

        // ---------------------------------------------------------------
        // Summary
        // ---------------------------------------------------------------
        console.log("");
        console.log("=== Chitin Shell Deployment Complete ===");
        console.log("AgentPolicy (Proxy):", address(policyProxy));
        console.log("AgentPolicy (Impl): ", address(policyImpl));
        console.log("PolicyGovernor:     ", address(policyGovernor));
        console.log("AuditLog:           ", address(auditLog));
        console.log("Deployer:           ", deployer);
        console.log("Governor 1:         ", gov1);
        console.log("Governor 2:         ", gov2);
        console.log("Required Approvals: ", requiredApprovals);
    }
}
