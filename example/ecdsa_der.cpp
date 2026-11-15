// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs with ECDSA the way a domain library does: a sighash computed by the library, a 64-byte
// signature, its strict DER form for the wire, and the low-S rule. The same signature has a
// twin with S replaced by n - S; accepting both makes transaction ids malleable, so verifiers
// refuse the high-S twin.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/hash2/sha2.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
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

void print(char const* name, std::span<std::uint8_t const> bytes) {
    std::printf("%s ", name);
    for (std::uint8_t const b : bytes) {
        std::printf("%02x", b);
    }
    std::printf("\n");
}

std::array<std::uint8_t, 32> sha256(std::span<std::uint8_t const> data) {
    boost::hash2::sha2_256 hash;
    hash.update(data.data(), data.size());
    auto const digest = hash.result();
    std::array<std::uint8_t, 32> out{};
    std::copy_n(digest.data(), out.size(), out.begin());
    return out;
}

// The secp256k1 group order, big-endian.
constexpr std::array<std::uint8_t, 32> order{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

// n - s on 32-byte big-endian numbers, from the last byte to the first with a borrow.
std::array<std::uint8_t, 32> order_minus(std::span<std::uint8_t const, 32> s) {
    std::array<std::uint8_t, 32> out{};
    int borrow = 0;
    for (std::size_t i = out.size(); i-- > 0;) {
        int const difference = order[i] - s[i] - borrow;
        borrow = difference < 0 ? 1 : 0;
        out[i] = static_cast<std::uint8_t>(difference + (borrow * 256));
    }
    return out;
}

}  // namespace

int main() {
    // A fixed secret keeps the output the same on every run: ECDSA here is deterministic
    // (RFC 6979), so the same key and hash always give the same signature.
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x11);
    auto key = secp256k1::keypair::make(secret);
    wipe(std::as_writable_bytes(std::span(secret)));
    if (!key) {
        return 1;
    }
    auto const public_key = key->public_key();
    if (!public_key) {
        return 1;
    }

    // tag::sign[]
    // The domain library decides what is signed: here a double SHA-256 of its own preimage.
    std::string_view const preimage = "example preimage";
    auto const first = sha256(std::span<std::uint8_t const>(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<std::uint8_t const*>(preimage.data()), preimage.size()));
    auto const sighash = sha256(first);
    auto const signature = key->sign_ecdsa(sighash);
    if (!signature) {
        return 1;
    }
    std::array<std::uint8_t, secp256k1::max_der_size> der{};
    auto const der_size = secp256k1::to_der(*signature, der);
    if (!der_size) {
        return 1;
    }
    print("der", std::span<std::uint8_t const>(der).first(*der_size));
    // end::sign[]

    auto const parsed = secp256k1::from_der(std::span<std::uint8_t const>(der).first(*der_size));
    if (!parsed || *parsed != *signature) {
        return 1;
    }
    std::printf("strict der round trip ok\n");
    if (!secp256k1::verify_ecdsa(*signature, sighash, *public_key)) {
        return 1;
    }
    std::printf("verified\n");

    // tag::normalize[]
    // The high-S twin: same r, s replaced by n - s.
    auto high = *signature;
    auto const flipped = order_minus(std::span<std::uint8_t const, 64>(high).last<32>());
    std::ranges::copy(flipped, high.begin() + 32);
    auto const refused = secp256k1::verify_ecdsa(high, sighash, *public_key);
    if (refused || refused.error() != crypto::error::invalid_signature) {
        return 1;
    }
    std::printf("high-S refused: invalid_signature\n");
    // A signature from elsewhere can be brought to the low-S form before it is checked.
    auto const normalized = secp256k1::normalize_ecdsa(high);
    if (!normalized || *normalized != *signature ||
        !secp256k1::verify_ecdsa(*normalized, sighash, *public_key)) {
        return 1;
    }
    std::printf("normalized to low-S: verified\n");
    // end::normalize[]
    return 0;
}

// end::program[]
