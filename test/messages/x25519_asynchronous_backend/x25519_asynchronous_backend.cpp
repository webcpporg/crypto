// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An X25519 key pair's from_secret, generate and agree (through the free crypto::agree) on a
// backend that completes by itself (a stand-in whose detail::asynchronous_backend_v is true) each
// stop with the refusal that names its asynchronous form, and with those errors alone: no engine
// is reached. The key pair and the peer are parameters of agree's caller, since making them would
// run the stand-in's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/x25519.hpp:* {{webcpp::crypto: from_secret on this backend completes asynchronously: call async_from_secret.}}
// expected-error@webcpp/crypto/curves/x25519.hpp:* {{webcpp::crypto: generate on this backend completes asynchronously: call async_generate.}}
// expected-error@webcpp/crypto/curves/x25519.hpp:* {{webcpp::crypto: agree on this backend completes asynchronously: call async_agree.}}
// clang-format on
#include <webcpp/crypto/curves/x25519.hpp>
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

using keypair = webcpp::crypto::curves::x25519::basic_keypair<stand_in_browser>;

/** Makes a key pair from its secret key on the stand-in. */
bool made(std::array<std::uint8_t, 32> const& secret_key) {
    return keypair::from_secret(secret_key).has_value();
}

/** Draws a key pair on the stand-in. */
bool drawn() {
    return keypair::generate().has_value();
}

/** Agrees with a key pair of the stand-in's. */
bool agreed(keypair const& key, webcpp::crypto::curves::x25519::public_key const& peer) {
    return webcpp::crypto::agree(key, peer).has_value();
}

}  // namespace

// The functions are compiled, which is the test; they are never run.
int main() {
    static_cast<void>(&made);
    static_cast<void>(&drawn);
    static_cast<void>(&agreed);
    return 0;
}
