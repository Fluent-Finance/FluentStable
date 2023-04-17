// This FluentStable contract is a custom ERC20 token with additional minting and burning functionality,
// controlled by a signer and a trusted safe address.
pragma solidity ^0.8.19;
// SPDX-License-Identifier: GPL-2.0-only

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract FluentStable is ERC20 {
    using ECDSA for bytes32;
    // The signer is an address responsible for authorizing mint operations.
    address public signer;
    // The trustedSafeAddress is an address responsible for executing mintWithSafe operations.
    address public trustedSafeAddress;
    // The _usedRhashes mapping keeps track of used rhashes to prevent replay attacks.
    mapping(bytes32 => bool) private _usedRhashes;
    // symbol keeps track of the symbol of the token
    uint8 private decimal;
    // network keep track of network this contract is deployed for
    string public network;

    // Event emitted when the signer is updated.
    event SignerUpdated(
        address indexed previousSigner,
        address indexed newSigner
    );
    // Event emitted when the trusted safe address is updated.
    event trustedSafeAddressUpdated(
        address indexed previousSafeAddress,
        address indexed newSafeAddress
    );
    // Event emitted when tokens are minted using the mint function.
    event Minted(
        address indexed to,
        uint256 amount,
        bytes32 rhash,
        string network
    );
    // Event emitted when tokens are minted using the mintWithSafe function.
    event MintedWithSafe(address indexed to, uint256 amount, string network);
    // Event emitted when tokens are burned.
    event Burned(address indexed from, uint256 amount, string network);

    // Constructor initializes the contract with a name, symbol, signer, and trusted safe address.
    constructor(
        string memory _name,
        string memory _symbol,
        string memory _network,
        uint8 _decimal,
        address _signer,
        address _trustedSafeAddress
    ) ERC20(_name, _symbol) {
        signer = _signer;
        trustedSafeAddress = _trustedSafeAddress;
        network = _network;
        decimal = _decimal;
    }

    // Overrides the decimals function of ERC20 to return a fixed value of 6.
    function decimals() public view override(ERC20) returns (uint8) {
        return decimal;
    }

    // Updates the signer to a new address.
    function updateSigner(address newSigner) public {
        require(
            newSigner != address(0),
            "FluentStable: new signer is the zero address"
        );
        require(msg.sender == signer, "FluentStable: caller is not the signer");

        emit SignerUpdated(signer, newSigner);
        signer = newSigner;
    }

    // Updates the trusted safe address to a new address.
    function updateTrustedSafeAddress(address newtrustedSafeAddress) public {
        require(
            newtrustedSafeAddress != address(0),
            "FluentStable: new safe address is the zero address"
        );
        require(
            msg.sender == trustedSafeAddress,
            "FluentStable: caller is not the current safe address"
        );

        emit trustedSafeAddressUpdated(
            trustedSafeAddress,
            newtrustedSafeAddress
        );
        trustedSafeAddress = newtrustedSafeAddress;
    }

    // Mints tokens to the specified recipient if the provided signature is valid.
    function mint(
        string memory iNetwork,
        string memory iSymbol,
        uint256 amount,
        address to,
        uint256 timestamp,
        bytes memory signature
    ) external {
        // Generate the message hash based on the provided parameters.
        bytes32 message = generateMessageHash(iNetwork, iSymbol, amount, to, timestamp);

        // Ensure the rhash has not been used before to prevent replay attacks.
        require(
            keccak256(abi.encodePacked(iNetwork)) ==
                keccak256(abi.encodePacked(network)),
            "FluentStable: Invalid network"
        );

        // ensure symbol is correct
        require(
            keccak256(abi.encodePacked(iSymbol)) ==
                keccak256(abi.encodePacked(symbol())),
            "FluentStable: Invalid token symbol"
        );

        // Ensure the rhash has not been used before to prevent replay attacks.
        require(!_usedRhashes[message], "FluentStable: rhash already used");

        // Verify the provided signature is valid for the generated message hash.
        verifySignature(message, signature);

        // Mark the rhash as used.
        _usedRhashes[message] = true;
        // Mint the tokens to the recipient.
        _mint(to, amount);

        // Emit the Minted event.
        emit Minted(to, amount, message, network);
    }

    // Mints tokens to the specified recipient using the trusted safe address.
    function mintWithSafe(uint256 amount, address recipient) public {
        // Ensure the caller is the trusted safe address.
        require(
            msg.sender == trustedSafeAddress,
            "FluentStable: Only the trusted safe address can call mintWithSafe"
        );
        // Mint the tokens to the recipient.
        _mint(recipient, amount);
        // Emit the MintedWithSafe event.
        emit MintedWithSafe(recipient, amount, network);
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
        emit Burned(from, amount, network);
    }

    // Returns whether the provided rhash has been used before.
    function isRhashUsed(bytes32 rhash) public view returns (bool) {
        return _usedRhashes[rhash];
    }

    // Generates a message hash based on the provided parameters.
    function generateMessageHash(
        string memory iNetwork,
        string memory iSymbol,
        uint256 amount,
        address account,
        uint256 timestamp
    ) public pure returns (bytes32) {
        return
            keccak256(abi.encodePacked(iNetwork, iSymbol, amount, account, timestamp));
    }

    // Verifies the provided signature is valid for the given message.
    function verifySignature(
        bytes32 message,
        bytes memory signature
    ) public view {
        // Recover the signer address from the signature.
        address proposedSigner = message.toEthSignedMessageHash().recover(
            signature
        );
        // Ensure the recovered signer matches the stored signer.
        require(proposedSigner == signer, "FluentStable: Invalid signature");
    }
}
