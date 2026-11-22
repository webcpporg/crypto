// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Alice and Bob of RFC 7748 section 6.1 agree a shared secret from each other's public keys;
// then two Ed25519 key pairs, made from RFC 8032's seeds, agree one through their X25519 forms;
// and a peer key of low order is refused. Prints each public key and the shared secrets in hex.
// tag::program[]
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace x25519 = webcpp::crypto::curves::x25519;

namespace {

// Prints bytes in hex after a name.
void print(char const* name, std::span<std::uint8_t const> bytes) {
    std::printf("%s ", name);
    for (auto const byte : bytes) {
        std::printf("%02x", byte);
    }
    std::printf("\n");
}

// X25519: each side sends its public key and keeps its secret key.
bool alice_and_bob() {
    // RFC 7748 section 6.1's secret keys: published, never real keys; a program draws its own
    // 32 bytes with random_device.
    std::array<std::uint8_t, 32> const alice_secret{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
        0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
        0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    std::array<std::uint8_t, 32> const bob_secret{
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
        0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
        0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    };
    auto const alice_public = x25519::public_key(alice_secret);
    auto const bob_public = x25519::public_key(bob_secret);
    if (!alice_public || !bob_public) {
        return false;
    }
    print("alice public", *alice_public);
    print("bob public  ", *bob_public);
    auto const alice_shared = x25519::agree(alice_secret, *bob_public);
    auto const bob_shared = x25519::agree(bob_secret, *alice_public);
    if (!alice_shared || !bob_shared) {
        return false;
    }
    // Printed here only because RFC 7748 publishes it; a program never prints a shared secret,
    // and derives its keys from it with a KDF.
    print("shared      ", alice_shared->bytes());
    return crypto::equal(alice_shared->bytes(), bob_shared->bytes());
}

// The same agreement from Ed25519 key pairs: one seed for signatures and key agreement.
bool from_ed25519() {
    std::array<std::uint8_t, 32> const first_seed{
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
        0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
        0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };
    std::array<std::uint8_t, 32> const second_seed{
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3,
        0x46, 0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab,
        0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    };
    auto const first = ed25519::keypair::make(first_seed);
    auto const second = ed25519::keypair::make(second_seed);
    if (!first || !second) {
        return false;
    }
    auto const first_secret = first->x25519_secret();
    auto const second_secret = second->x25519_secret();
    auto const first_signing = first->public_key();
    auto const second_signing = second->public_key();
    if (!first_secret || !second_secret || !first_signing || !second_signing) {
        return false;
    }
    // Each side knows the other by its Ed25519 public key, and converts it.
    auto const first_peer = ed25519::to_x25519_public(second_signing->bytes());
    auto const second_peer = ed25519::to_x25519_public(first_signing->bytes());
    if (!first_peer || !second_peer) {
        return false;
    }
    print("converted   ", *second_peer);
    auto const first_shared = x25519::agree(first_secret->bytes(), *first_peer);
    auto const second_shared = x25519::agree(second_secret->bytes(), *second_peer);
    return first_shared && second_shared &&
           crypto::equal(first_shared->bytes(), second_shared->bytes());
}

// A peer key of low order gives an all-zero secret, which agree refuses.
bool low_order_refused() {
    std::array<std::uint8_t, 32> const secret_key{1};
    std::array<std::uint8_t, 32> const zero_point{};
    auto const shared = x25519::agree(secret_key, zero_point);
    if (!shared && shared.error() == crypto::error::weak_public_key) {
        std::printf("low order    refused: weak_public_key\n");
        return true;
    }
    return false;
}

}  // namespace

int main() {
    if (!alice_and_bob() || !from_ed25519() || !low_order_refused()) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("agreed\n");
    return 0;
}

// end::program[]
