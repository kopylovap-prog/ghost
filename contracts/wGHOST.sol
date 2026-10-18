// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title wGHOST - ERC20 wrapper of native GHOST on Ethereum.
/// @notice Minted by the Ghost bridge quorum when native GHOST is locked on
///         the Ghost chain; burned to release native GHOST back.
///         Tradeable on Uniswap V2/V3 like any ERC20.
/// @dev AUDIT REQUIRED before any mainnet deployment.
contract WGHOST {
    string public constant name = "Wrapped Ghost";
    string public constant symbol = "wGHOST";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// Bridge quorum signers (validator-set style; rotate via updateQuorum).
    address[] public quorum;
    uint256 public quorumThreshold;

    /// Ghost lock tx hashes already minted (replay guard: 1 lock = 1 mint).
    mapping(bytes32 => bool) private usedLock;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Minted(address indexed to, uint256 value, bytes32 ghostTxHash);
    event Burned(address indexed from, uint256 value, string ghostRecipient);
    event QuorumUpdated(address[] members, uint256 threshold);

    constructor(address[] memory members_, uint256 threshold_) {
        quorum = members_;
        quorumThreshold = threshold_;
        emit QuorumUpdated(members_, threshold_);
    }

    // ------------------------------------------------------------------
    // ERC20
    // ------------------------------------------------------------------

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "wGHOST: allowance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - value;
        }
        _move(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function _move(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "wGHOST: balance");
        unchecked {
            balanceOf[from] -= value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
    }

    // ------------------------------------------------------------------
    // Bridge side
    // ------------------------------------------------------------------

    /// @notice Mint wGHOST after a quorum attests a GHOST lock tx.
    /// @param to      EVM address receiving wGHOST
    /// @param value   wei-amount (18 decimals after bridge scaling)
    /// @param ghostTxHash blake3 hash of the native GHOST lock tx
    /// @param sigs    65-byte (r,s,v) signatures over
    ///                keccak256(abi.encodePacked("ghost-lock-v1", to, value, ghostTxHash)),
    ///                sorted by signer address ascending, no duplicates.
    function mint(
        address to,
        uint256 value,
        bytes32 ghostTxHash,
        bytes[] calldata sigs
    ) external {
        require(!usedLock[ghostTxHash], "wGHOST: used");
        usedLock[ghostTxHash] = true;
        bytes32 digest = keccak256(
            abi.encodePacked("ghost-lock-v1", to, value, ghostTxHash)
        );
        _checkQuorum(digest, sigs);
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
        emit Minted(to, value, ghostTxHash);
    }

    /// @notice Burn wGHOST to request native GHOST release.
    ///         Bridge relayers watch the Burned event.
    function burn(uint256 value, string calldata ghostRecipient) external {
        require(balanceOf[msg.sender] >= value, "wGHOST: balance");
        unchecked {
            balanceOf[msg.sender] -= value;
            totalSupply -= value;
        }
        emit Transfer(msg.sender, address(0), value);
        emit Burned(msg.sender, value, ghostRecipient);
    }

    function _checkQuorum(bytes32 digest, bytes[] calldata sigs) internal view {
        require(sigs.length >= quorumThreshold, "wGHOST: not enough sigs");
        uint256 distinct;
        address prev = address(0);
        for (uint256 i = 0; i < sigs.length; i++) {
            require(sigs[i].length == 65, "wGHOST: sig len");
            bytes calldata sig = sigs[i];
            bytes32 r;
            bytes32 s;
            uint8 v;
            require(uint8(sig[64]) < 2, "wGHOST: v");
            r = bytes32(sig[0:32]);
            s = bytes32(sig[32:64]);
            v = uint8(sig[64]) + 27;
            address signer = ecrecover(digest, v, r, s);
            require(signer > prev, "wGHOST: sig order"); // dup + sorted check
            prev = signer;
            if (_isMember(signer)) {
                distinct += 1;
            }
        }
        require(distinct >= quorumThreshold, "wGHOST: quorum");
    }

    function _isMember(address a) internal view returns (bool) {
        for (uint256 i = 0; i < quorum.length; i++) {
            if (quorum[i] == a) return true;
        }
        return false;
    }
}
