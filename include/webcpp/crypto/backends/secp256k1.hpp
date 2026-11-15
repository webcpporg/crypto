// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend libsecp256k1: its v0.8.0, built from its sources by `/third_party//secp256k1`,
 every module on, with its `contrib/lax_der_parsing.c`. It serves `secp256k1::keypair`,
 `verify_schnorr`, `verify_ecdsa` and the DER and low-S functions, and its whole C API stays
 reachable through `<secp256k1*.h>`.

 @see "secp256k1", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_SECP256K1_HPP
#define WEBCPP_CRYPTO_BACKENDS_SECP256K1_HPP

#include <webcpp/crypto/config.hpp>

#ifndef WEBCPP_CRYPTO_HAS_SECP256K1
#error \
    "webcpp::crypto: <webcpp/crypto/secp256k1.hpp> needs libsecp256k1, which is not linked. In the program's Jamfile, add /third_party//secp256k1 beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_SECP256K1=1 and link libsecp256k1 built with webcpp's src/canary_secp256k1.c)"
#else

#include <webcpp/crypto/detail/canary.h>
#include <webcpp/crypto/detail/engines.hpp>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_schnorrsig.h>

#include <string_view>

// The configuration the canary names: the tables third_party/Jamfile built.
#ifdef WEBCPP_CRYPTO_SECP256K1_CANARY_CONFIGURATION
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION WEBCPP_CRYPTO_SECP256K1_CANARY_CONFIGURATION
#elif defined(WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES)
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION w2c2x5
#else
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION w15c11x6
#endif
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY                              \
    WEBCPP_CRYPTO_DETAIL_CANARY(secp256k1, WEBCPP_CRYPTO_SECP256K1_COMMIT, \
                                WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                           \
    "webcpp_crypto_backend_secp256k1",                                             \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(secp256k1, WEBCPP_CRYPTO_SECP256K1_COMMIT, \
                                        WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION))
#endif

extern "C" const char WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY;

// libsecp256k1's contrib/lax_der_parsing.c, which /third_party//secp256k1 compiles unmodified;
// its header stays out of the user's include path, so its prototype is declared here, exactly.
// A program that compiles its own copy of the file, as the file suggests, defines the same
// function: the static library's member is then not linked.
extern "C" int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx,
                                             secp256k1_ecdsa_signature* sig,
                                             const unsigned char* input, size_t inputlen);

namespace webcpp::crypto::backends {

/** The backend libsecp256k1 (spec section 3.5). */
struct secp256k1 {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "secp256k1";
};

}  // namespace webcpp::crypto::backends

#endif  // WEBCPP_CRYPTO_HAS_SECP256K1
#endif  // WEBCPP_CRYPTO_BACKENDS_SECP256K1_HPP
