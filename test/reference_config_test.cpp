// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto/config.hpp> read as MrDocs reads it, __MRDOCS__ defined, as the reference of a
// library that includes crypto reads it on that library's target: each macro a build sets comes
// out of the header defined exactly when the build defined it, whatever the header documents, and
// no refusal stops the reference. test/Jamfile builds this file with __MRDOCS__ on every target,
// and with the macros the refusals read: the memory option, natively without OpenSSL and on
// WebAssembly; version 0.1's two defines; OpenSSL on Emscripten. The refusals themselves still
// stop a program, as the message tests of test/messages show.

#ifndef __MRDOCS__
#error "test/Jamfile builds this file with __MRDOCS__ defined, as MrDocs reads the headers"
#endif

// What the build defined, before config.hpp reads it.
#ifdef WEBCPP_CRYPTO_NO_EXCEPTIONS
#define WEBCPP_TEST_BUILD_NO_EXCEPTIONS
#endif
#ifdef WEBCPP_CRYPTO_NO_THREADS
#define WEBCPP_TEST_BUILD_NO_THREADS
#endif
#ifdef WEBCPP_CRYPTO_HAS_BEARSSL
#define WEBCPP_TEST_BUILD_HAS_BEARSSL
#endif
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
#define WEBCPP_TEST_BUILD_HAS_OPENSSL
#endif
#ifdef WEBCPP_CRYPTO_HAS_CTAES
#define WEBCPP_TEST_BUILD_HAS_CTAES
#endif
#ifdef WEBCPP_CRYPTO_HAS_SODIUM
#define WEBCPP_TEST_BUILD_HAS_SODIUM
#endif
#ifdef WEBCPP_CRYPTO_HAS_SECP256K1
#define WEBCPP_TEST_BUILD_HAS_SECP256K1
#endif
#ifdef WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES
#define WEBCPP_TEST_BUILD_SMALL_TABLES
#endif
#ifdef WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE
#define WEBCPP_TEST_BUILD_MEMORY_RESOURCE
#endif

#include <webcpp/crypto/config.hpp>

#if defined(WEBCPP_TEST_BUILD_NO_THREADS) != defined(WEBCPP_CRYPTO_NO_THREADS)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_NO_THREADS is defined"
#endif
#if defined(WEBCPP_TEST_BUILD_HAS_BEARSSL) != defined(WEBCPP_CRYPTO_HAS_BEARSSL)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_HAS_BEARSSL is defined"
#endif
#if defined(WEBCPP_TEST_BUILD_HAS_OPENSSL) != defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_HAS_OPENSSL is defined"
#endif
#if defined(WEBCPP_TEST_BUILD_HAS_CTAES) != defined(WEBCPP_CRYPTO_HAS_CTAES)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_HAS_CTAES is defined"
#endif
#if defined(WEBCPP_TEST_BUILD_HAS_SODIUM) != defined(WEBCPP_CRYPTO_HAS_SODIUM)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_HAS_SODIUM is defined"
#endif
#if defined(WEBCPP_TEST_BUILD_HAS_SECP256K1) != defined(WEBCPP_CRYPTO_HAS_SECP256K1)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_HAS_SECP256K1 is defined"
#endif
#if defined(WEBCPP_TEST_BUILD_SMALL_TABLES) != defined(WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES is defined"
#endif
#if defined(WEBCPP_TEST_BUILD_MEMORY_RESOURCE) != defined(WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE is defined"
#endif
// A build with exceptions leaves it as the build set it; one without defines it, as always.
#if defined(WEBCPP_HAS_EXCEPTIONS) && \
    defined(WEBCPP_TEST_BUILD_NO_EXCEPTIONS) != defined(WEBCPP_CRYPTO_NO_EXCEPTIONS)
#error "under MrDocs, config.hpp changes whether WEBCPP_CRYPTO_NO_EXCEPTIONS is defined"
#endif

// The value a build gives survives too, not only the definition.
#if defined(WEBCPP_TEST_CRYPTO_SECP256K1_VALUE) && WEBCPP_CRYPTO_HAS_SECP256K1 != 2
#error "under MrDocs, config.hpp replaces the value the build gave WEBCPP_CRYPTO_HAS_SECP256K1"
#endif

int main() {
    return 0;
}
