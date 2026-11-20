// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Finds who signed a message without being sent their key, as Ethereum finds a transaction's
// signer: a wallet signs a message's hash with a recoverable signature, and a reader that holds
// no key recovers the signer's public key from the signature and the hash, then compares it
// with the key the wallet published. Recovery always finds some key, so the comparison is the
// check: a changed message recovers another key.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>

#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
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

// The message's SHA-256. Ethereum's own message hash is EIP-191's (a prefix, then Keccak-256),
// which a domain library computes; crypto signs and recovers whatever 32-byte hash it is given.
std::array<std::uint8_t, 32> sha256(std::string_view text) {
    boost::hash2::sha2_256 hash;
    hash.update(text.data(), text.size());
    auto const digest = hash.result();
    std::array<std::uint8_t, 32> out{};
    std::copy_n(digest.data(), out.size(), out.begin());
    return out;
}

boost::system::result<secp256k1::keypair> generate_key() {
    crypto::random_device device;
    std::array<std::uint8_t, 32> secret{};
    for (;;) {
        auto const filled = device.fill(secret);
        if (!filled) {
            return filled.error();
        }
        auto key = secp256k1::keypair::make(secret);
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
    auto const published = wallet->public_key_uncompressed();
    std::string message = "pay 10 to bob";
    auto const signature = wallet->sign_recoverable(sha256(message));
    if (!published || !signature) {
        return 1;
    }

    // tag::recover[]
    // The reader holds no key of the wallet's: it parses the published key once, recovers the
    // signer's key from the 65-byte signature and the hash, and compares the two.
    auto const expected = secp256k1::parse_public_key(*published);
    auto const signer = secp256k1::recover(*signature, sha256(message));
    if (!expected || !signer || *signer != *expected) {
        return 1;
    }
    std::printf("recovered the wallet's key\n");

    // A changed message still recovers a key, but not the wallet's.
    message = "pay 99 to bob";
    auto const other = secp256k1::recover(*signature, sha256(message));
    if (other && *other == *expected) {
        return 1;
    }
    std::printf("a changed message names another signer\n");
    // end::recover[]
    return 0;
}

// end::program[]
