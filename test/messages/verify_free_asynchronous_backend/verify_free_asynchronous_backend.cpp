// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free crypto::verify of P-256 against a key of a backend that completes by itself (a
// stand-in whose detail::asynchronous_backend_v is true) stops with the refusal that names
// async_verify, and with that error alone: no engine is reached. The key is a parameter, since
// making one would run the stand-in's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/p256.hpp:* {{webcpp::crypto: verify on this backend completes asynchronously: call async_verify.}}
// clang-format on
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that completes by itself, as part B's browser backend will. */
struct stand_in_browser {};

}  // namespace

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

namespace {

/** Verifies with a key of the stand-in's. */
bool verified(webcpp::crypto::curves::p256::basic_public_key<stand_in_browser> const& public_key) {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 64> const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return crypto::verify(crypto::ecdsa_sha256, signature, message, public_key).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&verified);
    return 0;
}
