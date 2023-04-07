// This FluentStable contract is a custom ERC20 token with additional minting and burning functionality,
// controlled by a signer and a trusted safe address.
pragma solidity ^0.8.19;
// SPDX-License-Identifier: GPL-2.0-only

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract FluentStable is ERC20 {
    using ECDSA for bytes32;
    // The signer is an address responsible for authorizing mint operations.
    address private _signer;
    // The trustedSafeAddress is an address responsible for executing mintWithSafe operations.
    address private _trustedSafeAddress;
    // The _usedRhashes mapping keeps track of used rhashes to prevent replay attacks.
    uint8 private _decimal;
    mapping(bytes32 => bool) private _usedRhashes;

    // Event emitted when the signer is updated.
    event SignerUpdated(
        address indexed previousSigner,
        address indexed newSigner
    );
    // Event emitted when the trusted safe address is updated.
    event TrustedSafeAddressUpdated(
        address indexed previousSafeAddress,
        address indexed newSafeAddress
    );
    // Event emitted when tokens are minted using the mint function.
    event Minted(address indexed to, uint256 amount, bytes32 rhash);
    // Event emitted when tokens are minted using the mintWithSafe function.
    event MintedWithSafe(address indexed to, uint256 amount);
    // Event emitted when tokens are burned.
    event Burned(address indexed from, uint256 amount);

    // Constructor initializes the contract with a name, symbol, signer, and trusted safe address.
    constructor(
        string memory name,
        string memory symbol,
        uint8 decimal,
        address signer,
        address trustedSafeAddress
    ) ERC20(name, symbol) {
        _signer = signer;
        _trustedSafeAddress = trustedSafeAddress;
        _decimal = decimal;
    }

    // Overrides the decimals function of ERC20 to return a fixed value of 6.
    function decimals() public view override(ERC20) returns (uint8) {
        return _decimal;
    }

    // Returns the signer address.
    function printSigner() public view returns (address) {
        return _signer;
    }

    // Returns the trusted safe address.
    function printTrustedSafeAddress() public view returns (address) {
        return _trustedSafeAddress;
    }

    // Updates the signer to a new address.
    function updateSigner(address newSigner) public {
        require(
            newSigner != address(0),
            "FluentStable: new signer is the zero address"
        );
        require(msg.sender == _signer, "FluentStable: caller is not the signer");

        emit SignerUpdated(_signer, newSigner);
        _signer = newSigner;
    }

    // Updates the trusted safe address to a new address.
    function updateTrustedSafeAddress(address newTrustedSafeAddress) public {
        require(
            newTrustedSafeAddress != address(0),
            "FluentStable: new safe address is the zero address"
        );
        require(
            msg.sender == _trustedSafeAddress,
            "FluentStable: caller is not the current safe address"
        );

        emit TrustedSafeAddressUpdated(
            _trustedSafeAddress,
            newTrustedSafeAddress
        );
        _trustedSafeAddress = newTrustedSafeAddress;
    }

    // Mints tokens to the specified recipient if the provided signature is valid.
    function mint(
        string memory network,
        uint256 amount,
        address to,
        uint256 nonce,
        uint256 timestamp,
        bytes32 rhash,
        bytes memory signature
    ) external {
        // Ensure the rhash has not been used before to prevent replay attacks.
        require(!_usedRhashes[rhash], "FluentStable: rhash already used");

        // Generate the message hash based on the provided parameters.
        bytes32 message = generateMessageHash(
            network,
            amount,
            to,
            nonce,
            timestamp
        );
        // Ensure the provided rhash matches the generated message hash.
        require(message == rhash, "FluentStable: Invalid rhash");
        // Verify the provided signature is valid for the generated message hash.
        verifySignature(message, signature);

        // Mark the rhash as used.
        _usedRhashes[rhash] = true;
        // Mint the tokens to the recipient.
        _mint(to, amount);

        // Emit the Minted event.
        emit Minted(to, amount, rhash);
    }

    // Mints tokens to the specified recipient using the trusted safe address.
    function mintWithSafe(uint256 amount, address recipient) public {
        // Ensure the caller is the trusted safe address.
        require(
            msg.sender == _trustedSafeAddress,
            "FluentStable: Only the trusted safe address can call mintWithSafe"
        );
        // Mint the tokens to the recipient.
        _mint(recipient, amount);
        // Emit the MintedWithSafe event.
        emit MintedWithSafe(recipient, amount);
    }

    // Burns tokens from the specified address.
    function burn(uint256 amount, address from) public {
        // Ensure the caller is the owner of the tokens to be burned.
        require(
            from == msg.sender,
            "FluentStable: Caller can only burn their own tokens"
        );
        // Burn the tokens.
        _burn(from, amount);
        // Emit the Burned event.
        emit Burned(from, amount);
    }

    // Returns whether the provided rhash has been used before.
    function isRhashUsed(bytes32 rhash) public view returns (bool) {
        return _usedRhashes[rhash];
    }

    // Generates a message hash based on the provided parameters.
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

    // Verifies the provided signature is valid for the given message.
    function verifySignature(
        bytes32 message,
        bytes memory signature
    ) public view {
        // Recover the signer address from the signature.
        address signer = message.toEthSignedMessageHash().recover(signature);
        // Ensure the recovered signer matches the stored signer.
        require(signer == _signer, "FluentStable: Invalid signature");
    }
}
