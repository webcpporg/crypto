// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// curves::secp256k1::silent_payments refuses a backend other than libsecp256k1 where it is
// instantiated, with the family's generated refusal, which names the backends that have
// it (design D33).

// clang-format off
// expected-error@webcpp/crypto/curves/secp256k1/silent_payments.hpp:* {{webcpp::crypto: bearssl has no BIP 352 silent payments. The backends that have it: secp256k1 (native, wasip2, wasip3, emscripten).}}
// clang-format on
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
