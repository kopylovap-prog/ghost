// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {WGHOST} from "./wGHOST.sol";

/// @notice Deploy the wGHOST bridge token with a 3-of-N quorum.
///
/// Local dev (anvil defaults, threshold 2):
///     cd contracts && forge install foundry-rs/forge-std
///     anvil &  forge script wGHOSTDeploy --broadcast
///
/// Sepolia:
///     export SIGNER_1=0xAAA... SIGNER_2=0xBBB... SIGNER_3=0xCCC...
///     export QUORUM_THRESHOLD=2
///     forge script wGHOSTDeploy --rpc-url $SEPOLIA_RPC_URL \
///         --private-key $DEPLOYER_KEY --broadcast --verify
///
/// After deployment call set_wghost(addr) on the ghost-dex side.
contract wGHOSTDeploy is Script {
    function run() external {
        // Anvil well-known accounts as defaults for local testing.
        address s1 = vm.envOr("SIGNER_1", 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        address s2 = vm.envOr("SIGNER_2", 0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
        address s3 = vm.envOr("SIGNER_3", 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC);
        uint256 threshold = vm.envOr("QUORUM_THRESHOLD", uint256(2));

        address[] memory members = new address[](3);
        members[0] = s1;
        members[1] = s2;
        members[2] = s3;

        vm.startBroadcast();
        new WGHOST(members, threshold);
        vm.stopBroadcast();
    }
}
