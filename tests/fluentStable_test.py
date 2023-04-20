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
        token_name,
        token_symbol,
        "Ethereum",
        6,
        accounts[9],
        signer,
        trusted_safe_address,
        {"from": deployer},
    )

    # Assert
    assert FluentStable.name() == token_name
    assert FluentStable.symbol() == token_symbol
    assert FluentStable.signer() == signer
    assert FluentStable.trustedSafeAddress() == trusted_safe_address


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
        "Ethereum",
        6,
        accounts[9],
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
    assert FluentStable.signer() == new_signer
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
        "Ethereum",
        6,
        accounts[9],
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
    assert FluentStable.trustedSafeAddress() == new_trusted_safe_address
    assert "trustedSafeAddressUpdated" in tx.events
    assert (
        tx.events["trustedSafeAddressUpdated"]["previousSafeAddress"]
        == initial_trusted_safe_address
    )
    assert (
        tx.events["trustedSafeAddressUpdated"]["newSafeAddress"]
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
        "Ethereum",
        6,
        accounts[9],
        str(signer.address),
        initial_trusted_safe_address.address,
        {"from": deployer},
    )

    recipient = accounts[3]
    incorrect_signer = Account.from_key(incorrect_signer_key)

    network = "Ethereum"
    amount = 1000
    timestamp = int(time.time())

    message_hash = generate_message_hash(
        network, token_symbol, amount, recipient, timestamp
    )

    # Generate valid and invalid signatures
    valid_signature = sign_message_hash(message_hash, signer)
    invalid_signature = sign_message_hash(message_hash, incorrect_signer)

    assert FluentStable.verifySignature(message_hash, valid_signature) == ()

    # Test minting with a valid rhash and signature
    tx = FluentStable.mint(
        network,
        token_symbol,
        amount,
        recipient,
        timestamp,
        valid_signature,
        {"from": recipient},
    )
    assert FluentStable.balanceOf(recipient) == amount
    assert FluentStable.isRhashUsed(message_hash) == True

    # Test minting with a invalid hash and valid signature
    with reverts("FluentStable: Invalid signature"):
        FluentStable.mint(
            network,
            token_symbol,
            amount + 100,
            recipient,
            timestamp,
            invalid_signature,
            {"from": recipient},
        )
    # Test minting with a invalid network and valid signature
    with reverts("FluentStable: Invalid network"):
        FluentStable.mint(
            "Blah Blah",
            token_symbol,
            amount,
            recipient,
            timestamp,
            invalid_signature,
            {"from": recipient},
        )
    # Test minting with a invalid symbol and valid signature
    with reverts("FluentStable: Invalid token symbol"):
        FluentStable.mint(
            network,
            "FakeToken",
            amount,
            recipient,
            timestamp,
            invalid_signature,
            {"from": recipient},
        )
    # Test if rhash is being used
    with reverts("FluentStable: rhash already used"):
        FluentStable.mint(
            network,
            token_symbol,
            amount,
            recipient,
            timestamp,
            valid_signature,
            {"from": recipient},
        )
    # Test minting with an invalid signature
    with reverts("FluentStable: Invalid signature"):
        FluentStable.mint(
            network,
            token_symbol,
            amount,
            recipient,
            timestamp + 1,
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
        "Ethereum",
        6,
        accounts[9],
        deployer,
        initial_trusted_safe_address,
        {"from": deployer},
    )

    # Define test parameters
    network = "Ethereum"
    amount = 1000
    recipient = accounts[1]
    timestamp = int(time.time())

    # Call the generateMessageHash function from the Solidity contract
    contract_generated_hash = FluentStable.generateMessageHash(
        network, token_symbol, amount, recipient, timestamp
    )

    # Use the same logic to create the message hash in the test script
    script_generated_hash = Web3.solidityKeccak(
        ["string", "string", "uint256", "address", "uint256"],
        [network, token_symbol, amount, recipient.address, timestamp],
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
        "Ethereum",
        6,
        accounts[9],
        str(signer.address),
        initial_trusted_safe_address.address,
        {"from": deployer},
    )

    recipient = accounts[3]

    network = "Ethereum"
    amount = 1000
    timestamp = int(time.time())

    message_hash = generate_message_hash(
        network, token_symbol, amount, recipient, timestamp
    )

    # Generate valid signature
    valid_signature = sign_message_hash(message_hash, signer)

    # Test minting
    FluentStable.mint(
        network,
        token_symbol,
        amount,
        recipient,
        timestamp,
        valid_signature,
        {"from": recipient},
    )
    assert FluentStable.balanceOf(recipient) == amount

    # Check if rhash is used
    assert FluentStable.isRhashUsed(message_hash) == True

    # Generate an unused rhash
    unused_message_hash = generate_message_hash(
        network, token_symbol, amount, recipient, timestamp + 1
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
        token_name,
        token_symbol,
        "Ethereum",
        6,
        accounts[9],
        signer,
        trusted_safe_address,
        {"from": deployer},
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
        token_name,
        token_symbol,
        "Ethereum",
        6,
        accounts[9],
        signer,
        trusted_safe_address,
        {"from": deployer},
    )

    recipient = accounts[3]
    amount = 1000

    # Only the trusted safe address can call mintWithSafe
    with reverts("FluentStable: Only the trusted safe address can call mintWithSafe"):
        FluentStable.mintWithSafe(amount, recipient, {"from": deployer})

    # mintWithSafe should mint the specified amount to the recipient
    FluentStable.mintWithSafe(amount, recipient, {"from": trusted_safe_address})
    assert FluentStable.balanceOf(recipient) == amount


def generate_message_hash(network, symbol, amount, account, timestamp):
    return Web3.solidityKeccak(
        ["string", "string", "uint256", "address", "uint256"],
        [network, symbol, amount, account.address, timestamp],
    )


def sign_message_hash(message_hash, signer):
    msg = encode_defunct(message_hash)
    signedObject = Account.sign_message(msg, signer.privateKey)
    return signedObject.signature


def test_blacklist(accounts):
    # Deploy FluentStable contract
    deployer = accounts[0]
    signer = accounts[1]
    trusted_safe_address = accounts[2]
    token_name = "USPlus"
    token_symbol = "US+"
    blacklister = accounts[9]

    FluentStable = token.deploy(
        token_name,
        token_symbol,
        "Ethereum",
        6,
        blacklister,
        signer,
        trusted_safe_address,
        {"from": deployer},
    )

    # Blacklisting an address
    blacklisted_address = accounts[4]
    non_blacklisted_address = accounts[5]

    # Only the owner can blacklist an address
    with reverts("FluentStable: Only blacklister can blacklist addresses"):
        FluentStable.blacklist(blacklisted_address, {"from": signer})

    # Blacklist the address
    FluentStable.blacklist(blacklisted_address, {"from": blacklister})

    # Test transfer from a blacklisted address
    with reverts("FluentStable: Source address is blacklisted"):
        FluentStable.transfer(
            non_blacklisted_address, 100, {"from": blacklisted_address}
        )

    # Test transfer to a blacklisted address
    with reverts("FluentStable: Destination address is blacklisted"):
        FluentStable.transfer(
            blacklisted_address, 100, {"from": non_blacklisted_address}
        )


def test_update_blacklister(accounts):
    # Deploy FluentStable contract
    deployer = accounts[0]
    new_blacklister = accounts[1]
    signer = accounts[2]
    trusted_safe_address = accounts[3]
    token_name = "USPlus"
    token_symbol = "US+"
    blacklister = accounts[9]
    new_blacklister = accounts[8]
    random_address = accounts[7]

    FluentStable = token.deploy(
        token_name,
        token_symbol,
        "Ethereum",
        6,
        blacklister,
        signer,
        trusted_safe_address,
        {"from": deployer},
    )

    # Update the blacklister
    with reverts("FluentStable: Only blacklister can blacklist addresses"):
        FluentStable.blacklist(random_address, {"from": new_blacklister})

    with reverts("FluentStable: New blacklister cannot be the zero address"):
        FluentStable.updateBlacklister(
            "0x0000000000000000000000000000000000000000", {"from": blacklister}
        )

    FluentStable.updateBlacklister(new_blacklister, {"from": blacklister})

    # Test blacklisting with new blacklister
    FluentStable.blacklist(random_address, {"from": new_blacklister})
