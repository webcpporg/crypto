// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto spells out the names libsecp256k1 abbreviates (design D12, owner decision 14):
// secp256k1's tweaks are public_key_tweak_add, public_key_tweak_mul, public_key_negate,
// public_key_combine, secret_key_tweak_add, secret_key_tweak_mul and secret_key_negate, with no
// alias left at libsecp256k1's names. A program that still names one stops there, with those seven
// errors alone, although tweak.hpp is included. Each text is a substring: clang may add "did you
// mean" with the new name.

#include <webcpp/crypto/curves/secp256k1/tweak.hpp>

// clang-format off
// expected-error@+1 {{no member named 'pubkey_tweak_add' in namespace 'webcpp::crypto::curves::secp256k1'}}
using webcpp::crypto::curves::secp256k1::pubkey_tweak_add;
// expected-error@+1 {{no member named 'pubkey_tweak_mul' in namespace 'webcpp::crypto::curves::secp256k1'}}
using webcpp::crypto::curves::secp256k1::pubkey_tweak_mul;
// expected-error@+1 {{no member named 'pubkey_negate' in namespace 'webcpp::crypto::curves::secp256k1'}}
using webcpp::crypto::curves::secp256k1::pubkey_negate;
// expected-error@+1 {{no member named 'pubkey_combine' in namespace 'webcpp::crypto::curves::secp256k1'}}
using webcpp::crypto::curves::secp256k1::pubkey_combine;
// expected-error@+1 {{no member named 'seckey_tweak_add' in namespace 'webcpp::crypto::curves::secp256k1'}}
using webcpp::crypto::curves::secp256k1::seckey_tweak_add;
// expected-error@+1 {{no member named 'seckey_tweak_mul' in namespace 'webcpp::crypto::curves::secp256k1'}}
using webcpp::crypto::curves::secp256k1::seckey_tweak_mul;
// expected-error@+1 {{no member named 'seckey_negate' in namespace 'webcpp::crypto::curves::secp256k1'}}
using webcpp::crypto::curves::secp256k1::seckey_negate;
// clang-format on

int main() {
    return 0;
}
