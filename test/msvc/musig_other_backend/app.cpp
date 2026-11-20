// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// curves::secp256k1::musig named with another backend stops at the family's refusal: on MSVC the
// compile fails. The text is checked on clang, in test/messages/musig_other_backend.
#include <webcpp/crypto/curves/secp256k1/musig.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 66> const encoded{};
    auto const nonce = webcpp::crypto::curves::secp256k1::musig::parse_public_nonce<
        webcpp::crypto::backends::bearssl>(encoded);
    return nonce ? 0 : 1;
}
