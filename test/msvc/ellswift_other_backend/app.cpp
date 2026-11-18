// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// curves::secp256k1's ElligatorSwift named with another backend stops at the family's refusal: on
// MSVC the compile fails. The text is checked on clang, in test/messages/ellswift_other_backend.
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>

#include <array>
#include <cstdint>

int main() {
    std::array<std::uint8_t, 64> const encoded{};
    auto const key =
        webcpp::crypto::curves::secp256k1::ellswift_decode<webcpp::crypto::backends::bearssl>(
            encoded);
    static_cast<void>(key);
    return 0;
}
