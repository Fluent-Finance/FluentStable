pragma solidity ^0.8.19;
// SPDX-License-Identifier: GPL-2.0-only

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract USPlus is ERC20 {
    using ECDSA for bytes32;

    address private _signer;
    address private _trustedSafeAddress;
    mapping(string => bool) private _usedRhashes;

    event SignerUpdated(address indexed previousSigner, address indexed newSigner);
    event TrustedSafeAddressUpdated(address indexed previousTrustedSafeAddress, address indexed newTrustedSafeAddress);
    event Minted(address indexed to, uint256 amount, string rhash);
    event MintedWithSafe(address indexed to, uint256 amount);
    event Burned(address indexed from, uint256 amount, string rhash);

    constructor(string memory name, string memory symbol, address signer, address trustedSafeAddress) ERC20(name, symbol) {
        _signer = signer;
        _trustedSafeAddress = trustedSafeAddress;
    }

    function printSigner() public view returns (address) {
        return _signer;
    }

    function decimals() public pure override(ERC20) returns (uint8) {
        return 6;
    }

    function printTrustedSafeAddress() public view returns (address) {
        return _trustedSafeAddress;
    }

    function updateSigner(address newSigner) public {
        require(newSigner != address(0), "USPlus: new signer is the zero address");
        require(msg.sender == _signer, "USPlus: caller is not the signer");

        emit SignerUpdated(_signer, newSigner);
        _signer = newSigner;
    }

    function updateTrustedSafeAddress(address newTrustedSafeAddress) public {
        require(newTrustedSafeAddress != address(0), "USPlus: new trusted safe address is the zero address");
        require(msg.sender == _trustedSafeAddress, "USPlus: caller is not the current trusted safe address");

        emit TrustedSafeAddressUpdated(_trustedSafeAddress, newTrustedSafeAddress);
        _trustedSafeAddress = newTrustedSafeAddress;
    }

    function mint(
        string memory network,
        uint256 amount,
        address to,
        uint256 nonce,
        uint256 timestamp,
        string memory rhash,
        string memory signature
    ) external {
        require(!_usedRhashes[rhash], "USPlus: rhash already used");

        bytes32 message = generateMessageHash(network, amount, to, nonce, timestamp);
        require(keccak256(abi.encodePacked(message)) == keccak256(abi.encodePacked(rhash)), "USPlus: Invalid rhash");
        verifySignature(message, signature);

        _usedRhashes[rhash] = true;
        _mint(to, amount);

        emit Minted(to, amount, rhash);
    }

    function mintWithSafe(uint256 amount, address to) external {
        require(msg.sender == _trustedSafeAddress, "USPlus: caller is not the trusted safe address");

        _mint(to, amount);

        emit MintedWithSafe(to, amount);
    }

    function burn(
        string memory network,
        uint256 amount,
        address from,
        uint256 nonce,
        uint256 timestamp,
        string memory rhash,
        string memory signature
    ) external {
        require(!_usedRhashes[rhash], "USPlus: rhash already used");

        bytes32 message = generateMessageHash(network, amount, from, nonce, timestamp);
        require(keccak256(abi.encodePacked(message)) == keccak256(abi.encodePacked(rhash)), "USPlus: Invalid rhash");
                verifySignature(message, signature);

        _usedRhashes[rhash] = true;
        _burn(from, amount);

        emit Burned(from, amount, rhash);
    }

    function generateMessageHash(
        string memory network,
        uint256 amount,
        address account,
        uint256 nonce,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(network, amount, account, nonce, timestamp));
    }

    function verifySignature(bytes32 message, string memory signature) internal view {
        address signerAddress = message.toEthSignedMessageHash().recover(StringConversion.toBytes(signature));
        require(signerAddress == _signer, "USPlus: Invalid signature");
    }
}

library StringConversion {
    function toBytes(string memory str) internal pure returns (bytes memory) {
        return bytes(str);
    }
}
