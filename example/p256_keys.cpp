// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Makes a P-256 key pair from RFC 6979's key, prints its public key as the 65 bytes WebCrypto's
// exportKey("raw") gives, keeps its scalar and makes the same key pair from it again, then imports
// that public key as a peer's and refuses the same bytes with one bit changed. Draws a fresh key
// pair too, whose bytes differ on every run and are not printed.
// tag::program[]
#include <webcpp/crypto/curves/p256.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>

namespace p256 = webcpp::crypto::curves::p256;

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

}  // namespace

int main() {
    // RFC 6979 section A.2.5's key: a published scalar, never a real key.
    std::array<std::uint8_t, 32> const scalar{
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
        0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
        0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    };
    auto const key = p256::keypair::make(scalar);
    if (!key) {
        std::printf("failed\n");
        return 1;
    }
    auto const public_key = key->public_key();
    // Kept, the scalar stays a secret<32>, wiped when it goes; it makes the same key pair again.
    auto const kept = key->secret_scalar();
    if (!public_key || !kept) {
        std::printf("failed\n");
        return 1;
    }
    std::array<std::uint8_t, p256::public_key_size> const exported = public_key->uncompressed();
    // 65 bytes: the prefix 04, then x and y, 32 bytes each.
    std::printf("public key %02x, then x and y\n", exported[0]);
    print("x         ", std::span(exported).subspan(1, p256::coordinate_size));
    print("y         ", std::span(exported).subspan(1 + p256::coordinate_size));
    auto const reloaded = p256::keypair::make(kept->bytes());
    auto const reloaded_public = reloaded ? reloaded->public_key() : reloaded.error();
    bool const same = reloaded_public && reloaded_public->uncompressed() == exported;
    std::printf("reloaded   %s\n", same ? "same key" : "FAILED");

    // A peer's key arrives as bytes: made once into a public_key, which checks the point.
    auto const peer = p256::public_key::make(exported);
    std::printf("peer key   %s\n", peer ? "valid" : "refused");
    std::array<std::uint8_t, p256::public_key_size> tampered = exported;
    tampered.back() ^= 0x01U;
    auto const forged = p256::public_key::make(tampered);
    std::string const reason = forged ? std::string() : forged.error().message();
    std::printf("tampered   %s: %s\n", forged ? "valid" : "refused", reason.c_str());

    // A real program draws its key pair from the system's generator.
    auto const fresh = p256::keypair::generate();
    std::printf("generated  %s\n", fresh ? "a fresh key pair" : "FAILED");
    return 0;
}

// end::program[]
