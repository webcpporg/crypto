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

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>

namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

void print(char const* name, std::span<std::uint8_t const> bytes) {
    std::printf("%s ", name);
    for (std::uint8_t const b : bytes) {
        std::printf("%02x", b);
    }
    std::printf("\n");
}

// Signs message with key and checks the signature under the key's x-only public key.
bool sign_and_verify(secp256k1::keypair const& key, std::span<std::uint8_t const> message) {
    std::array<std::uint8_t, 32> const aux{};
    auto const public_key = key.xonly_public_key();
    auto const signature = key.sign_schnorr(message, aux);
    if (!public_key || !signature) {
        return false;
    }
    print("public key", *public_key);
    print("signature ", *signature);
    return secp256k1::verify_schnorr(*signature, message, *public_key).has_value();
}

}  // namespace

int main() {
    std::array<std::uint8_t, 32> secret{};
    secret.back() = 3;
    std::array<std::uint8_t, 32> const message{};
    auto key = secp256k1::keypair::make(secret);
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
