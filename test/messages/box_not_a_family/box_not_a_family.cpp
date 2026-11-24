// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// public_key_encryption::basic_box given a type that is no box family's, and no backend, stops with
// the families it takes, and with that error alone: the default backend is read for a box family in
// the type's place, so a type that has no default of its own adds no error before it.

// clang-format off
// expected-error@webcpp/crypto/public_key_encryption/box.hpp:* {{webcpp::crypto: public_key_encryption::basic_box takes a box family: families::box_xsalsa20poly1305 or families::box_xchacha20poly1305.}}
// clang-format on
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>

namespace {

/** A type that names no family, and so has no default backend. */
struct not_a_family {};

/**
 * Makes the box from a key pair and a peer's public key, which are parameters: making them would
 * call X25519's engine.
 */
bool made(webcpp::crypto::curves::x25519::keypair const& own_keypair,
          webcpp::crypto::curves::x25519::public_key const& peer_public_key) {
    using box = webcpp::crypto::public_key_encryption::basic_box<not_a_family>;
    return box::from_keys(own_keypair, peer_public_key).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&made);
    return 0;
}
