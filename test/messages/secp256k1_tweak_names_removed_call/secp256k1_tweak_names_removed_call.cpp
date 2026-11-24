// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What a program that still calls secp256k1's tweaks by libsecp256k1's names sees (design D12,
// owner decision 14): each call stops the build, with those seven errors alone, although tweak.hpp
// is included. The functions are compiled, never run.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

namespace secp = webcpp::crypto::curves::secp256k1;

/** Tweaks a public key through the removed names. */
bool public_key_tweaked(std::span<std::uint8_t const> key_bytes) {
    std::array<std::uint8_t, 32> tweak_bytes{};
    tweak_bytes.back() = 1;
    auto const parsed_key = secp::public_key::from_bytes(key_bytes);
    if (!parsed_key) {
        return false;
    }
    std::array<secp::public_key, 2> const keys{*parsed_key, *parsed_key};
    std::vector<std::byte> pointer_space(secp::combine_workspace_size(keys.size()));
    // clang-format off
    // expected-error@+2 {{no member named 'pubkey_tweak_add' in namespace 'webcpp::crypto::curves::secp256k1'}}
    // clang-format on
    bool const added = secp::pubkey_tweak_add(*parsed_key, tweak_bytes).has_value();
    // clang-format off
    // expected-error@+2 {{no member named 'pubkey_tweak_mul' in namespace 'webcpp::crypto::curves::secp256k1'}}
    // clang-format on
    bool const multiplied = secp::pubkey_tweak_mul(*parsed_key, tweak_bytes).has_value();
    // clang-format off
    // expected-error@+2 {{no member named 'pubkey_negate' in namespace 'webcpp::crypto::curves::secp256k1'}}
    // clang-format on
    bool const negated = secp::pubkey_negate(*parsed_key).has_value();
    // clang-format off
    // expected-error@+2 {{no member named 'pubkey_combine' in namespace 'webcpp::crypto::curves::secp256k1'}}
    // clang-format on
    bool const combined = secp::pubkey_combine(keys, pointer_space).has_value();
    return added && multiplied && negated && combined;
}

/** Tweaks a secret key through the removed names. */
bool secret_key_tweaked(std::array<std::uint8_t, 32> const& secret_key) {
    std::array<std::uint8_t, 32> tweak_bytes{};
    tweak_bytes.back() = 1;
    // clang-format off
    // expected-error@+2 {{no member named 'seckey_tweak_add' in namespace 'webcpp::crypto::curves::secp256k1'}}
    // clang-format on
    bool const added = secp::seckey_tweak_add(secret_key, tweak_bytes).has_value();
    // clang-format off
    // expected-error@+2 {{no member named 'seckey_tweak_mul' in namespace 'webcpp::crypto::curves::secp256k1'}}
    // clang-format on
    bool const multiplied = secp::seckey_tweak_mul(secret_key, tweak_bytes).has_value();
    // clang-format off
    // expected-error@+2 {{no member named 'seckey_negate' in namespace 'webcpp::crypto::curves::secp256k1'}}
    // clang-format on
    bool const negated = secp::seckey_negate(secret_key).has_value();
    return added && multiplied && negated;
}

}  // namespace

// The functions are compiled, which is the test; they are never run.
int main() {
    static_cast<void>(&public_key_tweaked);
    static_cast<void>(&secret_key_tweaked);
    return 0;
}
