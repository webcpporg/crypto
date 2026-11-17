// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair on its default, libsodium, not linked, stops where it is made: on MSVC the
// compile fails. The text is checked on clang, in test/messages/ed25519_default_not_linked.
#include <webcpp/crypto/curves/ed25519.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const seed{};
    return webcpp::crypto::curves::ed25519::keypair::make(seed) ? 0 : 1;
}
