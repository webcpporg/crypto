// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend libsecp256k1: its v0.8.0, built from its sources by `/third_party//secp256k1`,
 every module on. It serves `curves::secp256k1::keypair`, `verify_schnorr`, `verify_ecdsa`,
 `recover`, the parsed `public_key`, the DER and low-S functions, the x-only tweak, the tweaks
 and combination of `curves/secp256k1/tweak.hpp`, the SPKI and PKCS#8 of
 `curves/secp256k1/formats.hpp`, the ElligatorSwift of `curves/secp256k1/ellswift.hpp`, the
 MuSig2 of `curves/secp256k1/musig.hpp` and the silent payments of
 `curves/secp256k1/silent_payments.hpp`, and its whole C API stays reachable through
 `<secp256k1*.h>`.

 @see "secp256k1", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_SECP256K1_HPP
#define WEBCPP_CRYPTO_BACKENDS_SECP256K1_HPP

#include <webcpp/crypto/config.hpp>

#ifndef WEBCPP_CRYPTO_HAS_SECP256K1
#error \
    "webcpp::crypto: <webcpp/crypto/curves/secp256k1.hpp> needs libsecp256k1, which is not linked. In the program's Jamfile, add /third_party//secp256k1 beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_SECP256K1=1 and link libsecp256k1 built with webcpp's src/canary_secp256k1.c)"
#else

#include <webcpp/crypto/detail/canary.h>
#include <webcpp/crypto/detail/engines.hpp>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_silentpayments.h>

#include <string_view>

#ifdef WEBCPP_CRYPTO_SECP256K1_CANARY_CONFIGURATION
/** The configuration the canary names: a test's, here. */
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION WEBCPP_CRYPTO_SECP256K1_CANARY_CONFIGURATION
#elif defined(WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES)
/** The configuration the canary names: the small tables third_party/Jamfile built. */
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION w2c2x5
#else
/** The configuration the canary names: the large tables third_party/Jamfile built. */
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION w15c11x6
#endif
/** The canary's name, which every libsecp256k1 function of crypto reads. */
#define WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY                              \
    WEBCPP_CRYPTO_DETAIL_CANARY(secp256k1, WEBCPP_CRYPTO_SECP256K1_COMMIT, \
                                WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                           \
    "webcpp_crypto_backend_secp256k1",                                             \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(secp256k1, WEBCPP_CRYPTO_SECP256K1_COMMIT, \
                                        WEBCPP_CRYPTO_DETAIL_SECP256K1_CONFIGURATION))
#endif

// src/canary_secp256k1.c defines the canary with a constant, so its initialisation is static, never
// dynamic; constinit, on this declaration, states it.
extern "C" constinit const char WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY;

namespace webcpp::crypto::backends {

/** The backend libsecp256k1. @see "The backends", in the guide. */
struct secp256k1 {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "secp256k1";
};

}  // namespace webcpp::crypto::backends

#endif  // WEBCPP_CRYPTO_HAS_SECP256K1
#endif  // WEBCPP_CRYPTO_BACKENDS_SECP256K1_HPP
