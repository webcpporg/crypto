// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What a program that still summarises a transaction's inputs through
// silent_payments::make_prevouts_summary sees (design D12, R24): the call stops the build, with
// that error alone, although silent_payments.hpp is included. The function is compiled, never run.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

namespace secp = webcpp::crypto::curves::secp256k1;
namespace silent_payments = webcpp::crypto::curves::secp256k1::silent_payments;

/** Summarises the inputs through the removed name. */
bool inputs_summarised(std::span<secp::public_key const> input_keys) {
    std::array<std::uint8_t, silent_payments::outpoint_size> const outpoint{};
    std::vector<std::byte> summary_space(
        silent_payments::summary_workspace_size(0, input_keys.size()));
    // clang-format off
    // expected-error@+2 {{no member named 'make_prevouts_summary' in namespace 'webcpp::crypto::curves::secp256k1::silent_payments'}}
    // clang-format on
    return silent_payments::make_prevouts_summary(outpoint, {}, input_keys, summary_space)
        .has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&inputs_summarised);
    return 0;
}
