// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair named with BearSSL, which has no Ed25519, stops at the capability table's
// refusal: on MSVC the compile fails. The text is checked on clang, in
// test/messages/ed25519_on_bearssl.
#include <webcpp/crypto/curves/ed25519.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const seed{};
    return webcpp::crypto::curves::ed25519::basic_keypair<
               webcpp::crypto::backends::bearssl>::from_secret(seed)
               ? 0
               : 1;
}
