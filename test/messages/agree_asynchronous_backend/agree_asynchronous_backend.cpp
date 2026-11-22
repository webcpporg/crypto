// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A P-256 key pair's agree on a backend that completes by itself (a stand-in whose
// detail::asynchronous_backend_v is true), through the free crypto::agree, stops with the refusal
// that names async_agree, and with that error alone: no engine is reached. The key pair and the
// peer are parameters, since making them would run the stand-in's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/p256.hpp:* {{webcpp::crypto: agree on this backend completes asynchronously: call async_agree.}}
// clang-format on
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/keypair.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that completes by itself, as part B's browser backend will. */
struct stand_in_browser {};

}  // namespace

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

namespace {

/** Agrees with a key pair and a peer of the stand-in's. */
bool agreed(webcpp::crypto::curves::p256::basic_keypair<stand_in_browser> const& key,
            webcpp::crypto::curves::p256::basic_public_key<stand_in_browser> const& peer) {
    return webcpp::crypto::agree(key, peer).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&agreed);
    return 0;
}
