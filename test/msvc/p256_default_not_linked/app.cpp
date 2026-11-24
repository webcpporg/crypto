// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A P-256 key pair on its default, BearSSL, not linked, stops where it is made: on MSVC the
// compile fails. The text is checked on clang, in test/messages/p256_default_not_linked.
#include <webcpp/crypto/curves/p256.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    return webcpp::crypto::curves::p256::keypair::from_secret(scalar) ? 0 : 1;
}
