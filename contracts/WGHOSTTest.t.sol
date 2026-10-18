// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./wGHOST.sol";

/// Minimal e2e test for WGHOST (no forge-std dependency).
interface VmI {
    function addr(uint256 pk) external returns (address);
    function sign(uint256 pk, bytes32 digest)
        external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address) external;
    function expectRevert(bytes memory) external;
}

contract WGHOSTTest {
    VmI constant vm = VmI(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    WGHOST token;
    address holder;
    uint256 constant VALUE = 1000 ether;

    function setUp() public {
        holder = vm.addr(1);
        address[] memory members = new address[](1);
        members[0] = holder;
        token = new WGHOST(members, 1);
    }

    function _sig(bytes32 digest) internal returns (bytes[] memory sigs) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, digest);
        sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, bytes1(uint8(v - 27)));
    }

    function _digest(address to, uint256 value, bytes32 h)
        internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("ghost-lock-v1", to, value, h));
    }

    function testMintBurnFlow() public {
        bytes32 h = keccak256("xmr-lock-tx-1");
        bytes[] memory sigs = _sig(_digest(holder, VALUE, h));
        token.mint(holder, VALUE, h, sigs);
        assertEq(token.balanceOf(holder), VALUE, "mint balance");
        assertEq(token.totalSupply(), VALUE, "mint supply");

        vm.prank(holder);
        token.burn(VALUE, "ghost-recipient");
        assertEq(token.balanceOf(holder), 0, "burn balance");
        assertEq(token.totalSupply(), 0, "burn supply");
    }

    function testTransferApprove() public {
        bytes32 h = keccak256("xmr-lock-tx-2");
        token.mint(holder, VALUE, h, _sig(_digest(holder, VALUE, h)));

        vm.prank(holder);
        token.transfer(address(0xBEEF), 100);
        assertEq(token.balanceOf(address(0xBEEF)), 100, "transfer");

        vm.prank(holder);
        token.approve(address(0xCEEF), 50);
        vm.prank(address(0xCEEF));
        token.transferFrom(holder, address(0xCEEF), 50);
        assertEq(token.balanceOf(address(0xCEEF)), 50, "transferFrom");
        assertEq(token.balanceOf(holder), VALUE - 150, "residual");
    }

    function testRevertWrongDigestSig() public {
        bytes32 h = keccak256("xmr-lock-tx-3");
        // signature over a DIFFERENT digest -> recovered signer is not a member
        bytes[] memory sigs = _sig(keccak256("wrong-digest"));
        vm.expectRevert(bytes("wGHOST: quorum"));
        token.mint(holder, VALUE, h, sigs);
    }

    function testRevertDuplicateSigOrder() public {
        bytes32 h = keccak256("xmr-lock-tx-4");
        bytes32 d = _digest(holder, VALUE, h);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, d);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = abi.encodePacked(r, s, bytes1(uint8(v - 27)));
        sigs[1] = abi.encodePacked(r, s, bytes1(uint8(v - 27)));
        // duplicate signer violates the strictly-sorted requirement
        vm.expectRevert(bytes("wGHOST: sig order"));
        token.mint(holder, VALUE, h, sigs);
    }

    function testRevertOvermintDoubleUse() public {
        bytes32 h = keccak256("xmr-lock-tx-5");
        bytes[] memory sigs = _sig(_digest(holder, VALUE, h));
        token.mint(holder, VALUE, h, sigs);
        // same ghost tx hash minted twice -> supply inflation guard
        vm.expectRevert(bytes("wGHOST: used"));
        token.mint(holder, VALUE, h, sigs);
    }

    function assertEq(uint256 a, uint256 b, string memory what) internal pure {
        require(a == b, what);
    }
}
