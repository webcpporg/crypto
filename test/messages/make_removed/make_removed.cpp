// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// make is gone, member and free, with no alias (design D3c): a key pair is made by from_secret,
// and a program that still calls P-256's key pair's make or crypto::make stops at each call, with
// those errors alone.

#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/factories.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const scalar{1};
    // expected-error@+1 {{no member named 'make' in}}
    auto const member_made = crypto::curves::p256::keypair::make(scalar);
    // With the name unknown, clang reads `<` as a comparison and the key pair's type where a value
    // goes: two errors for the line, as a program that still calls it sees them.
    using keypair = crypto::curves::p256::keypair;
    // expected-error@+2 {{no member named 'make' in}}
    // expected-error@+1 {{unexpected type name 'keypair': expected expression}} (knock-on)
    auto const free_made = crypto::make<keypair>(scalar);
    return member_made && free_made ? 0 : 1;
}
