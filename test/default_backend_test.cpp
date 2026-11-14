// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto/config.hpp> chooses the default backend as spec section 5 does: the one
// the program selects; else natively the first linked of OpenSSL and BearSSL; else
// BearSSL, with WEBCPP_CRYPTO_DETAIL_NONE_LINKED when neither is linked. test/Jamfile
// builds this file once per combination, each on the targets where its answer holds, and
// tells it the answer through WEBCPP_TEST_CRYPTO_EXPECT_OPENSSL (else BearSSL) and
// WEBCPP_TEST_CRYPTO_EXPECT_NONE_LINKED.

#include <webcpp/crypto/config.hpp>

#include <type_traits>

namespace crypto = webcpp::crypto;

#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL) == defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_BEARSSL)
#error "exactly one of WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL and _BEARSSL is defined"
#endif

#ifdef WEBCPP_TEST_CRYPTO_EXPECT_OPENSSL
#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL
#error "the default backend is not OpenSSL"
#endif
static_assert(std::is_same_v<crypto::default_backend, crypto::backends::openssl>,
              "default_backend is not OpenSSL");
#else
#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULT_BEARSSL
#error "the default backend is not BearSSL"
#endif
static_assert(std::is_same_v<crypto::default_backend, crypto::backends::bearssl>,
              "default_backend is not BearSSL");
#endif

#if defined(WEBCPP_TEST_CRYPTO_EXPECT_NONE_LINKED) != defined(WEBCPP_CRYPTO_DETAIL_NONE_LINKED)
#error "WEBCPP_CRYPTO_DETAIL_NONE_LINKED is not defined exactly when no backend is linked"
#endif
