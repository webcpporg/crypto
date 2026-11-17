// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs RFC 8032's second Ed25519 test with a key pair made from its seed and verifies the
// signature with the public key alone; then signs the message "abc" given in two pieces with
// Ed25519ph, as RFC 8032's Ed25519ph test does, and verifies it. Prints each key and signature
// in hex.
// tag::program[]
#include <webcpp/crypto/curves/ed25519.hpp>

#include <boost/hash2/sha2.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

namespace ed25519 = webcpp::crypto::curves::ed25519;

namespace {

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

// Ed25519: one message in one call.
bool sign_whole() {
    // RFC 8032 section 7.1, TEST 2: a published seed, never a real key; a program draws its
    // own with keypair::generate().
    std::array<std::uint8_t, 32> const seed{
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3,
        0x46, 0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab,
        0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    };
    std::array<std::uint8_t, 1> const message{0x72};
    auto const key = ed25519::keypair::make(seed);
    if (!key) {
        return false;
    }
    auto const public_key = key->public_key();
    auto const signature = key->sign(message);
    if (!public_key || !signature) {
        return false;
    }
    print("public key", *public_key);
    print("signature ", *signature);
    // The verifier holds the public key, the message and the signature; nothing secret.
    return ed25519::verify(*public_key, message, *signature).has_value();
}

// Ed25519ph: the message given in pieces, as a large file is read, signed once at the end.
// webcpp::hash::sha2_512 names Boost.Hash2's sha2_512, the hash RFC 8032 fixes.
bool sign_in_pieces() {
    std::array<std::uint8_t, 32> const seed{
        0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77,
        0x58, 0x75, 0x20, 0x91, 0x1e, 0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19,
        0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
    };
    std::array<std::uint8_t, 1> const first{'a'};
    std::array<std::uint8_t, 2> const second{'b', 'c'};
    using signer = ed25519::ph<boost::hash2::sha2_512>;
    auto const key = ed25519::keypair::make(seed);
    auto signing = signer::begin();
    if (!key || !signing || !signing->update(first) || !signing->update(second)) {
        return false;
    }
    auto const public_key = key->public_key();
    auto const signature = signing->sign(*key);
    if (!public_key || !signature) {
        return false;
    }
    print("public key", *public_key);
    print("signature ", *signature);
    auto verifying = signer::begin();
    return verifying && verifying->update(first) && verifying->update(second) &&
           verifying->verify(*public_key, *signature).has_value();
}

}  // namespace

int main() {
    if (!sign_whole() || !sign_in_pieces()) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("verified\n");
    return 0;
}

// end::program[]
