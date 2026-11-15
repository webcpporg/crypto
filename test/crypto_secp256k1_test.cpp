// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto.hpp> in a program that links libsecp256k1 brings secp256k1's header: its
// branch for WEBCPP_CRYPTO_HAS_SECP256K1 compiles, and the key pair and both verifications
// are declared through it alone.

#include <webcpp/crypto.hpp>

#include <type_traits>

#ifndef WEBCPP_CRYPTO_HAS_SECP256K1
#error "the test needs /third_party//secp256k1, which defines WEBCPP_CRYPTO_HAS_SECP256K1"
#endif

namespace secp = webcpp::crypto::curves::secp256k1;

static_assert(std::is_same_v<secp::keypair::backend_type, webcpp::crypto::backends::secp256k1>);
static_assert(std::is_function_v<decltype(secp::verify_schnorr<>)>);
static_assert(std::is_function_v<decltype(secp::verify_ecdsa<>)>);

int main() {
    return 0;
}
