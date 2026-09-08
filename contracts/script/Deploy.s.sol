// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {AdmissibilityAnchor} from "../src/AdmissibilityAnchor.sol";

/// @title Deploy
/// @notice Deploys AdmissibilityAnchor to Base (or Base Sepolia).
///
/// @dev The contract takes no constructor arguments and has no owner to set, so deployment is a
///      single unparameterised transaction. That is the point: nothing about the deployed
///      instance depends on who deployed it, which means anyone can redeploy an identical
///      instance if this one is ever inconvenient to somebody.
///
///      Usage - Base Sepolia:
///
///        forge script script/Deploy.s.sol:Deploy \
///          --rpc-url base_sepolia --broadcast --verify -vvvv
///
///      Usage - Base mainnet:
///
///        forge script script/Deploy.s.sol:Deploy \
///          --rpc-url base --broadcast --verify -vvvv
///
///      Environment: PRIVATE_KEY (hex, 0x-prefixed) and ETHERSCAN_API_KEY for verification.
contract Deploy is Script {
    function run() external returns (AdmissibilityAnchor deployed) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        console2.log("chain id  :", block.chainid);
        console2.log("deployer  :", deployer);
        console2.log("balance   :", deployer.balance);

        vm.startBroadcast(deployerKey);
        deployed = new AdmissibilityAnchor();
        vm.stopBroadcast();

        console2.log("AdmissibilityAnchor deployed at:", address(deployed));
    }
}
