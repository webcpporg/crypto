// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs the SHA-256 digest of "sample" with RFC 6979's P-256 key and prints the signature, the
// RFC's own bytes, in the raw form WebCrypto uses; then its low-S form, which a protocol that
// requires low S sends, and its DER encoding, which X.509 carries; and verifies both forms with
// the public key alone, and refuses the digest of another message.
// tag::program[]
#include <webcpp/crypto/curves/p256.hpp>

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

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

// What is signed is a SHA-256 digest, as WebCrypto's ECDSA with SHA-256 hashes the message.
std::array<std::uint8_t, p256::digest_size> digest_of(std::string_view text) {
    std::array<std::uint8_t, p256::digest_size> digest{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    auto const* const bytes = reinterpret_cast<std::uint8_t const*>(text.data());
    std::span<std::uint8_t const> const message(bytes, text.size());
    if (!webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(digest, message)) {
        digest.fill(0);
    }
    return digest;
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
    auto const public_key = key ? key->public_key() : key.error();
    if (!public_key) {
        std::printf("failed\n");
        return 1;
    }
    auto const digest = digest_of("sample");

    // RFC 6979's nonce: no random number, the same signature for the same key and digest.
    auto const signature = key->sign_ecdsa(digest);
    if (!signature) {
        std::printf("failed\n");
        return 1;
    }
    print("signature ", *signature);

    // This S is high: a protocol that requires low S sends the normalized form instead.
    std::printf("low S      %s\n", p256::check_low_s(*signature) ? "yes" : "no");
    auto const low = p256::normalize_ecdsa(*signature);
    if (!low) {
        std::printf("failed\n");
        return 1;
    }
    print("low-S form", *low);

    // DER, for X.509 and OpenSSL: at most max_der_size bytes, its length returned.
    std::array<std::uint8_t, p256::max_der_size> der{};
    auto const length = p256::to_der(*low, der);
    if (!length) {
        std::printf("failed\n");
        return 1;
    }
    print("DER       ", std::span(der).first(*length));

    // The verifier holds the public key, the digest and the signature; nothing secret.
    auto const decoded = p256::from_der(std::span(der).first(*length));
    bool const both = p256::verify_ecdsa(*signature, digest, *public_key) && decoded &&
                      p256::verify_ecdsa(*decoded, digest, *public_key);
    std::printf("verified   %s\n", both ? "both forms" : "FAILED");
    auto const other = p256::verify_ecdsa(*signature, digest_of("test"), *public_key);
    std::printf("other text %s\n", other ? "verified" : other.error().message().c_str());
    return 0;
}

// end::program[]
