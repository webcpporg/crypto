// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// curves::secp256k1::silent_payments named with another backend stops at the family's refusal: on
// MSVC the compile fails. The text is checked on clang, in
// test/messages/silent_payments_other_backend.
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace sp = webcpp::crypto::curves::secp256k1::silent_payments;
    std::array<std::uint8_t, sp::outpoint_size> const outpoint{};
    auto const summary =
        sp::make_prevouts_summary<webcpp::crypto::backends::bearssl>(outpoint, {}, {}, {});
    return summary ? 0 : 1;
}
