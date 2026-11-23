// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs BIP340's first test vector with secp256k1 and verifies it, then tweaks the key pair by
// a 32-byte tweak, as a domain library derives one, and signs and verifies under the tweaked
// key. Prints each key and signature in hex.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

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

// Prints bytes in hex after a name, 32 bytes (64 digits) to a line, the lines after the first
// indented under the first, so that a long value stays readable on a narrow page.
void print(char const* name, std::span<std::uint8_t const> bytes) {
    int const indent = std::printf("%s ", name);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0 && i % 32 == 0) {
            std::printf("\n%*s", indent, "");
        }
        std::printf("%02x", bytes[i]);
    }
    std::printf("\n");
}

// Signs message with key and checks the signature under the key's x-only public key. The
// auxiliary randomness is BIP340's first vector's, 32 zero bytes, so that the output is the same
// on every run; sign(crypto::schnorr, message) alone draws fresh bytes, as BIP340 recommends.
bool sign_and_verify(secp256k1::keypair const& key, std::span<std::uint8_t const> message) {
    std::array<std::uint8_t, 32> const aux{};
    auto const public_key = key.public_key();
    auto const signature = key.sign(crypto::schnorr, message, aux);
    if (!public_key || !signature) {
        return false;
    }
    print("public key", public_key->xonly());
    print("signature ", *signature);
    return crypto::verify(crypto::schnorr, *signature, message, *public_key).has_value();
}

}  // namespace

int main() {
    // BIP340's first test vector key, public on purpose; a real secret is drawn from
    // random_device.
    std::array<std::uint8_t, 32> secret{};
    secret.back() = 3;
    std::array<std::uint8_t, 32> const message{};
    auto key = secp256k1::keypair::make(secret);
    wipe(std::as_writable_bytes(std::span(secret)));
    if (!key || !sign_and_verify(*key, message)) {
        return 1;
    }
    std::array<std::uint8_t, 32> tweak{};
    tweak.fill(0x01);
    if (!key->tweak_xonly(tweak) || !sign_and_verify(*key, message)) {
        return 1;
    }
    std::printf("verified\n");
    return 0;
}

// end::program[]
