pragma solidity ^0.8.19;
// SPDX-License-Identifier: GPL-2.0-only

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract USPlus is ERC20 {
    using ECDSA for bytes32;

    address private _signer;
    address private _trustedSafeAddress;
    mapping(bytes32 => bool) private _usedRhashes;

    event SignerUpdated(
        address indexed previousSigner,
        address indexed newSigner
    );
    event TrustedSafeAddressUpdated(
        address indexed previousSafeAddress,
        address indexed newSafeAddress
    );
    event Minted(address indexed to, uint256 amount, bytes32 rhash);
    event MintedWithSafe(address indexed to, uint256 amount);
    event Burned(address indexed from, uint256 amount);

    constructor(
        string memory name,
        string memory symbol,
        address signer,
        address trustedSafeAddress
    ) ERC20(name, symbol) {
        _signer = signer;
        _trustedSafeAddress = trustedSafeAddress;
    }

    function decimals() public pure override(ERC20) returns (uint8) {
        return 6;
    }

    function printSigner() public view returns (address) {
        return _signer;
    }

    function printTrustedSafeAddress() public view returns (address) {
        return _trustedSafeAddress;
    }

    function updateSigner(address newSigner) public {
        require(
            newSigner != address(0),
            "USPlus: new signer is the zero address"
        );
        require(msg.sender == _signer, "USPlus: caller is not the signer");

        emit SignerUpdated(_signer, newSigner);
        _signer = newSigner;
    }

    function updateTrustedSafeAddress(address newTrustedSafeAddress) public {
        require(
            newTrustedSafeAddress != address(0),
            "USPlus: new safe address is the zero address"
        );
        require(
            msg.sender == _trustedSafeAddress,
            "USPlus: caller is not the current safe address"
        );

        emit TrustedSafeAddressUpdated(
            _trustedSafeAddress,
            newTrustedSafeAddress
        );
        _trustedSafeAddress = newTrustedSafeAddress;
    }

    function mint(
        string memory network,
        uint256 amount,
        address to,
        uint256 nonce,
        uint256 timestamp,
        bytes32 rhash,
        bytes memory signature
    ) external {
        require(!_usedRhashes[rhash], "USPlus: rhash already used");

        bytes32 message = generateMessageHash(
            network,
            amount,
            to,
            nonce,
            timestamp
        );
        require(message == rhash, "USPlus: Invalid rhash");
        verifySignature(message, signature);

        _usedRhashes[rhash] = true;
        _mint(to, amount);

        emit Minted(to, amount, rhash);
    }

    function mintWithSafe(uint256 amount, address recipient) public {
        require(
            msg.sender == _trustedSafeAddress,
            "USPlus: Only the trusted safe address can call mintWithSafe"
        );
        _mint(recipient, amount);
        emit MintedWithSafe(recipient, amount);
    }

    function burn(uint256 amount, address from) public {
        require(
            from == msg.sender,
            "USPlus: Caller can only burn their own tokens"
        );
        _burn(from, amount);
        emit Burned(from, amount);
    }

    function isRhashUsed(bytes32 rhash) public view returns (bool) {
        return _usedRhashes[rhash];
    }

    function generateMessageHash(
        string memory network,
        uint256 amount,
        address account,
        uint256 nonce,
        uint256 timestamp
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(network, amount, account, nonce, timestamp)
            );
    }

    function verifySignature(
        bytes32 message,
        bytes memory signature
    ) public view {
        address signer = message.toEthSignedMessageHash().recover(signature);
        require(signer == _signer, "USPlus: Invalid signature");
    }
}
