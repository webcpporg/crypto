// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The first messages of a peer-to-peer connection whose key exchange looks like random bytes,
// as BIP 324's transport starts: each peer sends its public key as an ElligatorSwift encoding,
// 64 bytes with no recognisable prefix, and both compute the same shared secret from the two
// encodings. The secrets and the randomness are fixed here, so that the program runs the same
// each time; a real program draws all four from random_device. Nothing random is printed.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>

#include <array>
#include <cstdint>
#include <cstdio>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

std::array<std::uint8_t, 32> repeated(std::uint8_t value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(value);
    return bytes;
}

}  // namespace

int main() {
    // Each peer's key pair and the randomness of its encoding (random_device in a real program).
    auto const initiator = secp256k1::keypair::make(repeated(0x11));
    auto const responder = secp256k1::keypair::make(repeated(0x22));
    if (!initiator || !responder) {
        return 1;
    }

    // Each peer sends the 64 bytes ellswift_create makes from its key pair.
    auto const initiator_message = secp256k1::ellswift_create(*initiator, repeated(0x33));
    auto const responder_message = secp256k1::ellswift_create(*responder, repeated(0x44));
    if (!initiator_message || !responder_message) {
        return 1;
    }

    // Each message decodes to its sender's public key; any 64 bytes decode to some key.
    auto const initiator_key = initiator->public_key();
    auto const responder_key = responder->public_key();
    if (!initiator_key || !responder_key ||
        secp256k1::serialize_public_key(secp256k1::ellswift_decode(*initiator_message)) !=
            *initiator_key ||
        secp256k1::serialize_public_key(secp256k1::ellswift_decode(*responder_message)) !=
            *responder_key) {
        return 1;
    }
    std::printf("each 64-byte message decodes to its sender's key\n");

    // Both pass the two messages in the same order, the initiator's first, and name their own
    // side; the shared secret is the input of the protocol's key schedule, not a key itself.
    auto const initiator_secret = secp256k1::ellswift_xdh(
        *initiator, *initiator_message, *responder_message, secp256k1::ellswift_party::initiator);
    auto const responder_secret = secp256k1::ellswift_xdh(
        *responder, *initiator_message, *responder_message, secp256k1::ellswift_party::responder);
    if (!initiator_secret || !responder_secret ||
        !crypto::equal(initiator_secret->bytes(), responder_secret->bytes())) {
        return 1;
    }
    std::printf("initiator and responder agree\n");
    return 0;
}

// end::program[]
