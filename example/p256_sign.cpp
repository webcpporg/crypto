// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs "sample" with RFC 6979's P-256 key and prints the signature in the raw form WebCrypto
// uses, low S (the RFC's r, and n minus the RFC's high s); then its DER encoding, which X.509
// carries; and verifies the signature read back from DER with the public key alone, given the
// message and given its SHA-256 digest, and refuses another message.
// tag::program[]
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/hash/digest.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;
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

// A text's bytes, the message.
std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
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
    // tag::sign[]
    // The message itself: ECDSA over SHA-256 hashes it inside, as WebCrypto's ECDSA with SHA-256
    // signs. RFC 6979's nonce: no random number, the same signature for the same key and message.
    auto const signature = key->sign(crypto::ecdsa_sha256, bytes_of("sample"));
    // end::sign[]
    if (!signature) {
        std::printf("failed\n");
        return 1;
    }
    print("signature ", *signature);
    // Always low S: the RFC's own S is high, and sign gives n - s.
    std::printf("low S      %s\n", p256::is_low_s(*signature) ? "yes" : "no");

    // DER, for X.509 and OpenSSL: at most max_der_size bytes, its length returned.
    std::array<std::uint8_t, p256::max_der_size> der{};
    auto const length = p256::to_der(*signature, der);
    if (!length) {
        std::printf("failed\n");
        return 1;
    }
    print("DER       ", std::span(der).first(*length));

    // The verifier holds the public key, the message and the signature; nothing secret. A digest
    // computed elsewhere is marked as one, crypto::prehashed{digest}.
    auto const decoded = p256::from_der(std::span(der).first(*length));
    std::array<std::uint8_t, p256::digest_size> digest{};
    auto const hashed =
        webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(digest, bytes_of("sample"));
    bool const both =
        decoded && hashed &&
        crypto::verify(crypto::ecdsa_sha256, *decoded, bytes_of("sample"), *public_key) &&
        crypto::verify(crypto::ecdsa_sha256, *decoded, crypto::prehashed{digest}, *public_key);
    std::printf("verified   %s\n", both ? "message and digest" : "FAILED");
    auto const other =
        crypto::verify(crypto::ecdsa_sha256, *signature, bytes_of("test"), *public_key);
    std::string const outcome = other ? std::string("verified") : other.error().message();
    std::printf("other text %s\n", outcome.c_str());
    return 0;
}

// end::program[]
