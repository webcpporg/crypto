// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto spells out the names libsecp256k1 abbreviates (design D12, owner decision 14): MuSig2's
// nonce is made by musig::generate_nonce, with no alias left at libsecp256k1's nonce_gen. A
// program that still names it stops there, with that error alone, although musig.hpp is included.

#include <webcpp/crypto/curves/secp256k1/musig.hpp>

// clang-format off
// expected-error@+1 {{no member named 'nonce_gen' in namespace 'webcpp::crypto::curves::secp256k1::musig'}}
using webcpp::crypto::curves::secp256k1::musig::nonce_gen;
// clang-format on

int main() {
    return 0;
}
