// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free crypto::sign under crypto::eddsa_prehashed with an Ed25519 key pair of a backend that
// completes by itself (a stand-in whose detail::asynchronous_backend_v is true) stops at the key
// pair's sign, which it calls, at its first statement after the guard, with the refusal that says
// WebCrypto has no Ed25519ph, before the text that names async_sign, and with that error alone:
// no engine is reached. The key pair is a parameter, since making one would run the stand-in's
// engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, async_sign and async_verify run on a native backend.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
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

/** Signs a digest with a key pair of the stand-in's. */
bool signed_digest(webcpp::crypto::curves::ed25519::basic_keypair<stand_in_browser> const& key) {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 64> const digest{};
    return crypto::sign(key, crypto::eddsa_prehashed, crypto::prehashed{digest}).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&signed_digest);
    return 0;
}
