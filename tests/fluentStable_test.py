import pytest
from brownie import accounts, reverts
from brownie import FluentStable as token
from eth_account import Account
from eth_account.messages import encode_defunct
import time
from web3 import Web3


# Test the constructor function
def test_constructor():
    # Arrange
    deployer = accounts[0]
    signer = accounts[1]
    trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"

    # Act
    FluentStable = token.deploy(
        token_name, token_symbol, 6, signer, trusted_safe_address, {"from": deployer}
    )

    # Assert
    assert FluentStable.name() == token_name
    assert FluentStable.symbol() == token_symbol
    assert FluentStable.printSigner() == signer
    assert FluentStable.printTrustedSafeAddress() == trusted_safe_address


def test_update_signer():
    # Arrange
    deployer = accounts[0]
    initial_signer = accounts[1]
    new_signer = accounts[2]
    trusted_safe_address = accounts[3]
    token_name = "USPlus"
    token_symbol = "US+"

    FluentStable = token.deploy(
        token_name,
        token_symbol,
        6,
        initial_signer,
        trusted_safe_address,
        {"from": deployer},
    )

    # Act and Assert
    # Only the current signer can update the signer
    with reverts("FluentStable: caller is not the signer"):
        FluentStable.updateSigner(new_signer, {"from": deployer})

    # The new signer cannot be the zero address
    with reverts("FluentStable: new signer is the zero address"):
        FluentStable.updateSigner(
            "0x0000000000000000000000000000000000000000", {"from": initial_signer}
        )

    # Update the signer successfully
    tx = FluentStable.updateSigner(new_signer, {"from": initial_signer})
    assert FluentStable.printSigner() == new_signer
    assert "SignerUpdated" in tx.events
    assert tx.events["SignerUpdated"]["previousSigner"] == initial_signer
    assert tx.events["SignerUpdated"]["newSigner"] == new_signer


def test_update_trusted_safe_address():
    # Arrange
    deployer = accounts[0]
    signer = accounts[1]
    initial_trusted_safe_address = accounts[2]
    new_trusted_safe_address = accounts[3]
    token_name = "USPlus"
    token_symbol = "US+"

    FluentStable = token.deploy(
        token_name,
        token_symbol,
        6,
        signer,
        initial_trusted_safe_address,
        {"from": deployer},
    )

    # Act and Assert
    # Only the current trusted safe address can update the trusted safe address
    with reverts("FluentStable: caller is not the current safe address"):
        FluentStable.updateTrustedSafeAddress(
            new_trusted_safe_address, {"from": deployer}
        )

    # The new trusted safe address cannot be the zero address
    with reverts("FluentStable: new safe address is the zero address"):
        FluentStable.updateTrustedSafeAddress(
            "0x0000000000000000000000000000000000000000",
            {"from": initial_trusted_safe_address},
        )

    # Update the trusted safe address successfully
    tx = FluentStable.updateTrustedSafeAddress(
        new_trusted_safe_address, {"from": initial_trusted_safe_address}
    )
    assert FluentStable.printTrustedSafeAddress() == new_trusted_safe_address
    assert "TrustedSafeAddressUpdated" in tx.events
    assert (
        tx.events["TrustedSafeAddressUpdated"]["previousSafeAddress"]
        == initial_trusted_safe_address
    )
    assert (
        tx.events["TrustedSafeAddressUpdated"]["newSafeAddress"]
        == new_trusted_safe_address
    )


def test_mint(accounts):
    # Deploy FluentStable contract
    signer_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    incorrect_signer_key = (
        "0x6cfe566e6c2f4617a97b04f88f7a8086f3a6e3c6e1f6b13c0d2a7a97a77b0e88"
    )
    deployer = accounts[0]
    initial_trusted_safe_address = accounts[2]
    signer = Account.from_key(signer_key)
    token_name = "USPlus"
    token_symbol = "US+"

    FluentStable = token.deploy(
        token_name,
        token_symbol,
        6,
        str(signer.address),
        initial_trusted_safe_address.address,
        {"from": deployer},
    )

    recipient = accounts[3]
    incorrect_signer = Account.from_key(incorrect_signer_key)

    network = "Ethereum"
    amount = 1000
    nonce = 1
    timestamp = int(time.time())

    message_hash = generate_message_hash(network, amount, recipient, nonce, timestamp)

    # Generate valid and invalid signatures
    valid_signature = sign_message_hash(message_hash, signer)
    invalid_signature = sign_message_hash(message_hash, incorrect_signer)

    assert FluentStable.verifySignature(message_hash, valid_signature) == ()

    # Test minting with a valid rhash and signature
    tx = FluentStable.mint(
        network,
        amount,
        recipient,
        nonce,
        timestamp,
        message_hash,
        valid_signature,
        {"from": recipient},
    )
    assert FluentStable.balanceOf(recipient) == amount
    assert FluentStable.isRhashUsed(message_hash) == True

    # Test minting with an invalid rhash
    invalid_rhash = generate_message_hash(
        network, amount, recipient, nonce + 1000, timestamp
    )  # 1000 to invalidate the rhash
    with reverts("FluentStable: Invalid rhash"):
        FluentStable.mint(
            network,
            amount,
            recipient,
            nonce,
            timestamp,
            invalid_rhash,
            valid_signature,
            {"from": recipient},
        )

    # Test minting with an invalid signature
    message_hash = generate_message_hash(
        network, amount, recipient, nonce + 2, timestamp
    )
    with reverts("FluentStable: Invalid signature"):
        FluentStable.mint(
            network,
            amount,
            recipient,
            nonce + 2,
            timestamp,
            message_hash,
            invalid_signature,
            {"from": recipient},
        )


def test_generate_message_hash():
    # Deploy FluentStable contract

    deployer = accounts[0]
    initial_trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"
    FluentStable = token.deploy(
        token_name,
        token_symbol,
        6,
        deployer,
        initial_trusted_safe_address,
        {"from": deployer},
    )

    # Define test parameters
    network = "Ethereum"
    amount = 1000
    recipient = accounts[1]
    nonce = 42
    timestamp = int(time.time())

    # Call the generateMessageHash function from the Solidity contract
    contract_generated_hash = FluentStable.generateMessageHash(
        network, amount, recipient, nonce, timestamp
    )

    # Use the same logic to create the message hash in the test script
    script_generated_hash = Web3.solidityKeccak(
        ["string", "uint256", "address", "uint256", "uint256"],
        [network, amount, recipient.address, nonce, timestamp],
    )

    # Compare the results
    assert (
        contract_generated_hash == script_generated_hash.hex()
    ), "Generated message hashes do not match"


def test_ishashused(accounts):
    # Deploy FluentStable contract
    signer_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    deployer = accounts[0]
    initial_trusted_safe_address = accounts[2]
    signer = Account.from_key(signer_key)
    token_name = "USPlus"
    token_symbol = "US+"

    FluentStable = token.deploy(
        token_name,
        token_symbol,
        6,
        str(signer.address),
        initial_trusted_safe_address.address,
        {"from": deployer},
    )

    recipient = accounts[3]

    network = "Ethereum"
    amount = 1000
    nonce = 1
    timestamp = int(time.time())

    message_hash = generate_message_hash(network, amount, recipient, nonce, timestamp)

    # Generate valid signature
    valid_signature = sign_message_hash(message_hash, signer)

    # Test minting
    FluentStable.mint(
        network,
        amount,
        recipient,
        nonce,
        timestamp,
        message_hash,
        valid_signature,
        {"from": recipient},
    )
    assert FluentStable.balanceOf(recipient) == amount

    # Check if rhash is used
    assert FluentStable.isRhashUsed(message_hash) == True

    # Generate an unused rhash
    nonce += 1
    unused_message_hash = generate_message_hash(
        network, amount, recipient, nonce, timestamp
    )

    # Check if the new rhash is unused
    assert FluentStable.isRhashUsed(unused_message_hash) == False


def test_burn(accounts):
    # Deploy FluentStable contract
    deployer = accounts[0]
    trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"
    signer = accounts[1]

    FluentStable = token.deploy(
        token_name, token_symbol, 6, signer, trusted_safe_address, {"from": deployer}
    )

    # Mint tokens for the user
    user = accounts[3]
    amount_to_mint = 5000
    FluentStable.mintWithSafe(amount_to_mint, user, {"from": trusted_safe_address})
    assert FluentStable.balanceOf(user) == amount_to_mint

    # Burn tokens for the user using burn
    amount_to_burn = 2000
    FluentStable.burn(amount_to_burn, user, {"from": user})
    assert FluentStable.balanceOf(user) == amount_to_mint - amount_to_burn

    # Attempt to burn tokens from another account should fail
    another_user = accounts[4]
    with reverts("FluentStable: Caller can only burn their own tokens"):
        FluentStable.burn(amount_to_burn, another_user, {"from": user})


def test_mint_with_safe(accounts):
    deployer = accounts[0]
    signer = accounts[1]
    trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"

    FluentStable = token.deploy(
        token_name, token_symbol, 6, signer, trusted_safe_address, {"from": deployer}
    )

    recipient = accounts[3]
    amount = 1000

    # Only the trusted safe address can call mintWithSafe
    with reverts("FluentStable: Only the trusted safe address can call mintWithSafe"):
        FluentStable.mintWithSafe(amount, recipient, {"from": deployer})

    # mintWithSafe should mint the specified amount to the recipient
    FluentStable.mintWithSafe(amount, recipient, {"from": trusted_safe_address})
    assert FluentStable.balanceOf(recipient) == amount


def generate_message_hash(network, amount, account, nonce, timestamp):
    return Web3.solidityKeccak(
        ["string", "uint256", "address", "uint256", "uint256"],
        [network, amount, account.address, nonce, timestamp],
    )


def sign_message_hash(message_hash, signer):
    msg = encode_defunct(message_hash)
    signedObject = Account.sign_message(msg, signer.privateKey)
    return signedObject.signature
