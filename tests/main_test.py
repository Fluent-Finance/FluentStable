import pytest
from brownie import USPlus, accounts, reverts
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
    usplus = USPlus.deploy(
        token_name, token_symbol, signer, trusted_safe_address, {"from": deployer}
    )

    # Assert
    assert usplus.name() == token_name
    assert usplus.symbol() == token_symbol
    assert usplus.printSigner() == signer
    assert usplus.printTrustedSafeAddress() == trusted_safe_address


def test_update_signer():
    # Arrange
    deployer = accounts[0]
    initial_signer = accounts[1]
    new_signer = accounts[2]
    trusted_safe_address = accounts[3]
    token_name = "USPlus"
    token_symbol = "US+"

    usplus = USPlus.deploy(
        token_name,
        token_symbol,
        initial_signer,
        trusted_safe_address,
        {"from": deployer},
    )

    # Act and Assert
    # Only the current signer can update the signer
    with reverts("USPlus: caller is not the signer"):
        usplus.updateSigner(new_signer, {"from": deployer})

    # The new signer cannot be the zero address
    with reverts("USPlus: new signer is the zero address"):
        usplus.updateSigner(
            "0x0000000000000000000000000000000000000000", {"from": initial_signer}
        )

    # Update the signer successfully
    tx = usplus.updateSigner(new_signer, {"from": initial_signer})
    assert usplus.printSigner() == new_signer
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

    usplus = USPlus.deploy(
        token_name,
        token_symbol,
        signer,
        initial_trusted_safe_address,
        {"from": deployer},
    )

    # Act and Assert
    # Only the current trusted safe address can update the trusted safe address
    with reverts("USPlus: caller is not the current safe address"):
        usplus.updateTrustedSafeAddress(new_trusted_safe_address, {"from": deployer})

    # The new trusted safe address cannot be the zero address
    with reverts("USPlus: new safe address is the zero address"):
        usplus.updateTrustedSafeAddress(
            "0x0000000000000000000000000000000000000000",
            {"from": initial_trusted_safe_address},
        )

    # Update the trusted safe address successfully
    tx = usplus.updateTrustedSafeAddress(
        new_trusted_safe_address, {"from": initial_trusted_safe_address}
    )
    assert usplus.printTrustedSafeAddress() == new_trusted_safe_address
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
    # Deploy USPlus contract
    signer_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    incorrect_signer_key = (
        "0x6cfe566e6c2f4617a97b04f88f7a8086f3a6e3c6e1f6b13c0d2a7a97a77b0e88"
    )
    deployer = accounts[0]
    initial_trusted_safe_address = accounts[2]
    signer = Account.from_key(signer_key)
    token_name = "USPlus"
    token_symbol = "US+"

    usplus = USPlus.deploy(
        token_name,
        token_symbol,
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

    assert usplus.verifySignature(message_hash, valid_signature) == ()

    # Test minting with a valid rhash and signature
    tx = usplus.mint(
        network,
        amount,
        recipient,
        nonce,
        timestamp,
        message_hash,
        valid_signature,
        {"from": recipient},
    )
    assert usplus.balanceOf(recipient) == amount
    assert usplus.isRhashUsed(message_hash) == True

    # Test minting with an invalid rhash
    invalid_rhash = generate_message_hash(
        network, amount, recipient, nonce + 1000, timestamp
    )  # 1000 to invalidate the rhash
    with reverts("USPlus: Invalid rhash"):
        usplus.mint(
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
    with reverts("USPlus: Invalid signature"):
        usplus.mint(
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
    # Deploy USPlus contract

    deployer = accounts[0]
    initial_trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"
    usplus = USPlus.deploy(
        token_name,
        token_symbol,
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
    contract_generated_hash = usplus.generateMessageHash(
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


def test_burn(accounts):
    # Deploy USPlus contract
    signer_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    incorrect_signer_key = (
        "0x6cfe566e6c2f4617a97b04f88f7a8086f3a6e3c6e1f6b13c0d2a7a97a77b0e88"
    )
    deployer = accounts[0]
    initial_trusted_safe_address = accounts[2]
    signer = Account.from_key(signer_key)
    token_name = "USPlus"
    token_symbol = "US+"

    usplus = USPlus.deploy(
        token_name,
        token_symbol,
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

    # Mint tokens for the recipient
    usplus.mint(
        network,
        amount,
        recipient,
        nonce,
        timestamp,
        message_hash,
        valid_signature,
        {"from": recipient},
    )
    assert usplus.balanceOf(recipient) == amount

    # Burn tokens
    nonce += 1
    burn_amount = 500
    burn_message_hash = generate_message_hash(
        network, burn_amount, recipient, nonce, timestamp
    )

    # Generate valid and invalid signatures for burn
    valid_burn_signature = sign_message_hash(burn_message_hash, signer)
    invalid_burn_signature = sign_message_hash(burn_message_hash, incorrect_signer)

    # Test burning with a valid rhash and signature
    tx = usplus.burn(
        network,
        burn_amount,
        recipient,
        nonce,
        timestamp,
        burn_message_hash,
        valid_burn_signature,
        {"from": recipient},
    )
    assert usplus.balanceOf(recipient) == amount - burn_amount
    assert usplus.isRhashUsed(burn_message_hash) == True

    # Test burning with an invalid rhash
    nonce += 1
    invalid_burn_rhash = generate_message_hash(
        network, burn_amount, recipient, nonce + 1000, timestamp
    )  # 1000 to invalidate the rhash
    with reverts("USPlus: Invalid rhash"):
        usplus.burn(
            network,
            burn_amount,
            recipient,
            nonce,
            timestamp,
            invalid_burn_rhash,
            valid_burn_signature,
            {"from": recipient},
        )

    # Test burning with an invalid signature
    nonce += 1
    new_burn_message_hash = generate_message_hash(
        network, burn_amount, recipient, nonce, timestamp
    )
    with reverts("USPlus: Invalid signature"):
        usplus.burn(
            network,
            burn_amount,
            recipient,
            nonce,
            timestamp,
            new_burn_message_hash,
            invalid_burn_signature,
            {"from": recipient},
        )


def test_ishashused(accounts):
    # Deploy USPlus contract
    signer_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    deployer = accounts[0]
    initial_trusted_safe_address = accounts[2]
    signer = Account.from_key(signer_key)
    token_name = "USPlus"
    token_symbol = "US+"

    usplus = USPlus.deploy(
        token_name,
        token_symbol,
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
    usplus.mint(
        network,
        amount,
        recipient,
        nonce,
        timestamp,
        message_hash,
        valid_signature,
        {"from": recipient},
    )
    assert usplus.balanceOf(recipient) == amount

    # Check if rhash is used
    assert usplus.isRhashUsed(message_hash) == True

    # Generate an unused rhash
    nonce += 1
    unused_message_hash = generate_message_hash(
        network, amount, recipient, nonce, timestamp
    )

    # Check if the new rhash is unused
    assert usplus.isRhashUsed(unused_message_hash) == False


def test_mint_with_safe(accounts):
    deployer = accounts[0]
    signer = accounts[1]
    trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"

    usplus = USPlus.deploy(
        token_name, token_symbol, signer, trusted_safe_address, {"from": deployer}
    )

    recipient = accounts[3]
    amount = 1000

    # Only the trusted safe address can call mintWithSafe
    with reverts("USPlus: Only the trusted safe address can call mintWithSafe"):
        usplus.mintWithSafe(amount, recipient, {"from": deployer})

    # mintWithSafe should mint the specified amount to the recipient
    usplus.mintWithSafe(amount, recipient, {"from": trusted_safe_address})
    assert usplus.balanceOf(recipient) == amount


def test_burn_with_safe(accounts):
    deployer = accounts[0]
    signer = accounts[1]
    trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"

    usplus = USPlus.deploy(
        token_name, token_symbol, signer, trusted_safe_address, {"from": deployer}
    )

    recipient = accounts[3]
    amount = 1000

    # Mint some tokens to the recipient
    usplus.mintWithSafe(amount, recipient, {"from": trusted_safe_address})
    assert usplus.balanceOf(recipient) == amount

    # Only the trusted safe address can call burnWithSafe
    with reverts("USPlus: Only the trusted safe address can call burnWithSafe"):
        usplus.burnWithSafe(amount, recipient, {"from": deployer})

    # burnWithSafe should burn the specified amount from the recipient
    usplus.burnWithSafe(amount, recipient, {"from": trusted_safe_address})
    assert usplus.balanceOf(recipient) == 0


def generate_message_hash(network, amount, account, nonce, timestamp):
    return Web3.solidityKeccak(
        ["string", "uint256", "address", "uint256", "uint256"],
        [network, amount, account.address, nonce, timestamp],
    )


def sign_message_hash(message_hash, signer):
    msg = encode_defunct(message_hash)
    signedObject = Account.sign_message(msg, signer.privateKey)
    return signedObject.signature
