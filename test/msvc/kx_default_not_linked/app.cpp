// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// As test/messages/kx_default_not_linked: on MSVC the compile fails; the text is checked on clang
// there.

#include <webcpp/crypto/curves/x25519/kx.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 32> const seed{};
    return webcpp::crypto::curves::x25519::kx_keypair<>::make(seed) ? 0 : 1;
}
