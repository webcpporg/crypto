// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// make is gone, member and free, with no alias (design D3c): a key pair is made by from_secret,
// and a program that still calls P-256's key pair's make or crypto::make stops at each call, with
// those two errors alone.

#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/factories.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const scalar{1};
    // expected-error@+1 {{no member named 'make' in}}
    auto const member_made = crypto::curves::p256::keypair::make(scalar);
    // `template` reads the unknown name as a template's, as a program that called the old function
    // meant it, so that its arguments are not parsed as a comparison: one error for the line.
    // expected-error@+1 {{no member named 'make' in}}
    auto const free_made = crypto::template make<crypto::curves::p256::keypair>(scalar);
    return member_made && free_made ? 0 : 1;
}
