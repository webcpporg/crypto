// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519's verification given the signature as 64 bytes, a std::array, not as a
// curves::ed25519::signature, stops at Ed25519's verify, which names the type it takes and how to
// make one, and with that error alone: no verify takes a signature as bytes (design R1).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: verify: an Ed25519 key verifies a curves::ed25519::signature under crypto::eddsa: make one from 64 bytes with curves::ed25519::signature::from_bytes.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    auto const public_key =
        crypto::curves::ed25519::public_key::from_bytes(std::array<std::uint8_t, 32>{});
    std::array<std::uint8_t, 64> const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key && crypto::verify(crypto::eddsa, signature, message, *public_key) ? 0 : 1;
}
