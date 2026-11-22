// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An author signs a message with a BIP340 Schnorr signature and a reader verifies it with the
// author's public key alone. No server vouches for the message: any change to the text breaks
// the signature, so peers can trust what they receive from untrusted relays.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// The message is hashed to a fixed-size id, and the id is what gets signed.
std::array<std::uint8_t, 32> id_of(std::string_view text) {
    boost::hash2::sha2_256 hash;
    hash.update(text.data(), text.size());
    auto const digest = hash.result();
    std::array<std::uint8_t, 32> id{};
    std::copy_n(digest.data(), id.size(), id.begin());
    return id;
}

// tag::keygen[]
// Overwrites a secret through a volatile pointer, which the optimiser cannot drop as a dead
// store: crypto wipes its own copies of keys this way, and the program wipes its own.
void wipe(std::span<std::byte> secret) {
    std::byte volatile* const bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        bytes[i] = std::byte{0};
    }
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
        // Not every 32 bytes are a key (zero, or too large), which is astronomically rare:
        // draw again. Any other error is real.
        if (key || key.error() != crypto::error::invalid_secret_key) {
            // The key pair keeps its own copy, which it wipes; this one goes now.
            wipe(std::as_writable_bytes(std::span(secret)));
            return key;
        }
    }
}

// end::keygen[]

}  // namespace

int main() {
    auto author = generate_key();
    if (!author) {
        return 1;
    }
    auto const public_key = author->public_key();
    if (!public_key) {
        return 1;
    }

    // tag::sign[]
    auto const id = id_of("meet at noon");
    // sign draws 32 fresh auxiliary bytes, which make the signature unpredictable and guard
    // against fault attacks (BIP340).
    auto const signature = author->sign(crypto::schnorr, id);
    if (!signature) {
        return 1;
    }
    // end::sign[]

    // tag::verify[]
    // The reader needs only the message, the signature and the public key.
    if (!crypto::verify(crypto::schnorr, *signature, id_of("meet at noon"), *public_key)) {
        return 1;
    }
    std::printf("verified\n");
    auto const altered =
        crypto::verify(crypto::schnorr, *signature, id_of("meet at nine"), *public_key);
    if (altered || altered.error() != crypto::error::invalid_signature) {
        return 1;
    }
    std::printf("altered message refused: invalid_signature\n");
    // end::verify[]
    return 0;
}

// end::program[]
