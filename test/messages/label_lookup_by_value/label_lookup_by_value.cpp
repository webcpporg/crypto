// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A silent payments label lookup that returns the tweak by value, as a lookup over a map would
// with `return it->second;`: libsecp256k1 reads the tweak after the lookup returns, when a
// value returned is gone, so label_lookup accepts only a span into bytes the lookup owns.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace {

struct tweak_by_value_lookup {
    std::optional<std::array<std::uint8_t, 32>> operator()(
        std::span<std::uint8_t const, 33> /*candidate*/) const noexcept {
        return std::nullopt;
    }
};

}  // namespace

int main() {
    namespace secp = webcpp::crypto::curves::secp256k1;
    namespace sp = webcpp::crypto::curves::secp256k1::silent_payments;
    std::array<std::uint8_t, 32> secret_bytes{};
    secret_bytes.fill(0x11);
    auto const scan_key = secp::keypair::from_secret(secret_bytes);
    auto const spend_key = scan_key->public_key();
    std::array<secp::public_key, 1> const inputs{*spend_key};
    std::array<std::uint8_t, sp::outpoint_size> const outpoint{};
    std::vector<std::byte> space(sp::summary_workspace_size(0, 1));
    auto const summary = sp::make_previous_outputs_summary(outpoint, {}, inputs, space);
    std::array<std::array<std::uint8_t, 32>, 1> const outputs{};
    std::vector<sp::found_output> found(1);
    std::vector<std::byte> scan_space(sp::scan_workspace_size(1));
    // expected-error@+1 {{no matching function for call to 'scan_outputs'}}
    auto const count = sp::scan_outputs(*scan_key, *spend_key, *summary, outputs, found, scan_space,
                                        tweak_by_value_lookup{});
    // clang-format off
    // expected-note@webcpp/crypto/curves/secp256k1/silent_payments.hpp:* {{does not satisfy 'label_lookup'}}
    // expected-note@webcpp/crypto/curves/secp256k1/silent_payments.hpp:* {{because 'std::same_as<std::invoke_result_t<}}
    // clang-format on
    return count ? 0 : 1;
}
