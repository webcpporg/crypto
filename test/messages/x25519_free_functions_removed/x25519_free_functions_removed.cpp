// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// X25519's free functions over bytes are gone, with no alias (design D7): a key pair made by
// from_secret gives its public key and agrees with a peer's typed key. A program that still calls
// curves::x25519::agree(secret, peer) or curves::x25519::public_key(secret) stops at each call,
// with those errors alone: the first name is unknown, the second is the public key's type, which
// no secret converts to.

#include <webcpp/crypto/curves/x25519.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace x25519 = webcpp::crypto::curves::x25519;
    std::array<std::uint8_t, 32> const secret_key{1};
    std::array<std::uint8_t, 32> const peer_key{9};
    // expected-error@+1 {{no member named 'agree' in namespace 'webcpp::crypto::curves::x25519'}}
    auto const shared = x25519::agree(secret_key, peer_key);
    // expected-error@+1 {{no matching conversion for functional-style cast}}
    auto const own_key = x25519::public_key(secret_key);
    return 0;
}
