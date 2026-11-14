/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The canary of the backend libsecp256k1, compiled into /third_party//secp256k1 with
 * libsecp256k1's own defines. Its configuration is the precomputed tables those defines
 * make: w15c11x6, libsecp256k1's defaults (no define, window 15 and comb 11x6, src/ecmult.h
 * and src/ecmult_gen.h); w2c2x5, the small tables (window 2 and comb 2x5); and unconfigured
 * for any other build, which no header expects. */
#include <webcpp/crypto/detail/canary.h>

#if !defined(ECMULT_WINDOW_SIZE) && !defined(COMB_BLOCKS) && !defined(COMB_TEETH)
#define WEBCPP_CRYPTO_SECP256K1_BUILT w15c11x6
#elif defined(ECMULT_WINDOW_SIZE) && ECMULT_WINDOW_SIZE == 2 && defined(COMB_BLOCKS) && \
    COMB_BLOCKS == 2 && defined(COMB_TEETH) && COMB_TEETH == 5
#define WEBCPP_CRYPTO_SECP256K1_BUILT w2c2x5
#else
#define WEBCPP_CRYPTO_SECP256K1_BUILT unconfigured
#endif

#if defined(_MSC_VER)
#pragma detect_mismatch(                                                           \
    "webcpp_crypto_backend_secp256k1",                                             \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(secp256k1, WEBCPP_CRYPTO_SECP256K1_COMMIT, \
                                        WEBCPP_CRYPTO_SECP256K1_BUILT))
#endif

extern const char WEBCPP_CRYPTO_DETAIL_CANARY(secp256k1, WEBCPP_CRYPTO_SECP256K1_COMMIT,
                                              WEBCPP_CRYPTO_SECP256K1_BUILT);
const char WEBCPP_CRYPTO_DETAIL_CANARY(secp256k1, WEBCPP_CRYPTO_SECP256K1_COMMIT,
                                       WEBCPP_CRYPTO_SECP256K1_BUILT) = 0;
