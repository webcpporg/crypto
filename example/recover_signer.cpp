// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Finds who signed a message without being sent their key, as Ethereum finds a transaction's
// signer: a wallet signs a message with a recoverable signature, and a reader that holds no key
// recovers the signer's public key from the signature and the message, then compares it with
// the key the wallet published. Recovery always finds some key, so the comparison is the
// check: a changed message recovers another key.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// Overwrites a secret through a volatile pointer, which the optimiser cannot drop as a dead
// store: crypto wipes its own copies of keys this way, and the program wipes its own.
void wipe(std::span<std::byte> secret) {
    std::byte volatile* const bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        bytes[i] = std::byte{0};
    }
}

// A text's bytes, the message. crypto::ecdsa_sha256_recoverable hashes it with SHA-256 inside;
// Ethereum's own message hash is EIP-191's (a prefix, then Keccak-256), which a domain library
// computes and gives as crypto::prehashed{digest}.
std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

boost::system::result<secp256k1::keypair> generate_key() {
    crypto::random_device device;
    std::array<std::uint8_t, 32> secret{};
    for (;;) {
        auto const filled = device.fill(secret);
        if (!filled) {
            return filled.error();
        }
        auto key = secp256k1::keypair::from_secret(secret);
        if (key || key.error() != crypto::error::invalid_secret_key) {
            // The key pair keeps its own copy, which it wipes; this one goes now.
            wipe(std::as_writable_bytes(std::span(secret)));
            return key;
        }
    }
}

}  // namespace

int main() {
    // The wallet publishes its key once, uncompressed as Ethereum writes it, and signs.
    auto wallet = generate_key();
    if (!wallet) {
        return 1;
    }
    auto const wallet_key = wallet->public_key();
    std::string message = "pay 10 to bob";
    auto const signature = wallet->sign(crypto::ecdsa_sha256_recoverable, bytes_of(message));
    if (!wallet_key || !signature) {
        return 1;
    }
    auto const published = wallet_key->uncompressed();

    // tag::recover[]
    // The reader holds no key of the wallet's: it makes the published key once, recovers the
    // signer's key from the 65-byte signature and the message, and compares the two.
    auto const expected = secp256k1::public_key::from_bytes(published);
    auto const signer =
        secp256k1::recover(crypto::ecdsa_sha256_recoverable, *signature, bytes_of(message));
    if (!expected || !signer || *signer != *expected) {
        return 1;
    }
    std::printf("recovered the wallet's key\n");

    // A changed message still recovers a key, but not the wallet's.
    message = "pay 99 to bob";
    auto const other =
        secp256k1::recover(crypto::ecdsa_sha256_recoverable, *signature, bytes_of(message));
    if (other && *other == *expected) {
        return 1;
    }
    std::printf("a changed message names another signer\n");
    // end::recover[]
    return 0;
}

// end::program[]
