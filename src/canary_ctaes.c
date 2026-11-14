/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The canary of the backend ctaes, compiled into /third_party//ctaes. ctaes has one
 * configuration, so the canary's is default. */
#include <webcpp/crypto/detail/canary.h>

#if defined(WEBCPP_CRYPTO_CTAES_CANARY_CONFIGURATION)
#define WEBCPP_CRYPTO_CTAES_BUILT WEBCPP_CRYPTO_CTAES_CANARY_CONFIGURATION
#else
#define WEBCPP_CRYPTO_CTAES_BUILT default
#endif

#if defined(_MSC_VER)
#pragma detect_mismatch("webcpp_crypto_backend_ctaes", \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(ctaes, WEBCPP_CRYPTO_CTAES_COMMIT, WEBCPP_CRYPTO_CTAES_BUILT))
#endif

extern const char WEBCPP_CRYPTO_DETAIL_CANARY(ctaes, WEBCPP_CRYPTO_CTAES_COMMIT,
                                              WEBCPP_CRYPTO_CTAES_BUILT);
const char WEBCPP_CRYPTO_DETAIL_CANARY(ctaes, WEBCPP_CRYPTO_CTAES_COMMIT,
                                       WEBCPP_CRYPTO_CTAES_BUILT) = 0;
