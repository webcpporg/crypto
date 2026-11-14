// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The configuration of webcpp::crypto, which each of its headers includes first:
 whether it is built without exceptions, whether the target is WebAssembly, the
 backends the build links and the default backend.

 @see "Using webcpp::crypto in your Jamfile", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CONFIG_HPP
#define WEBCPP_CRYPTO_CONFIG_HPP

#include <webcpp/config.hpp>

// MrDocs parses crypto natively, as a build with exceptions does, where neither
// macro is defined: these definitions, each undone at once, are the ones the
// reference lists.
#ifdef __MRDOCS__
/**
 Defined when webcpp::crypto is built without exceptions: when webcpp has none (the
 compiler has none, or the developer defined `WEBCPP_NO_EXCEPTIONS` for every webcpp
 library), or when the developer defines it alone.

 Every operation reports its errors as values whether or not it is defined. The random
 device's `operator()`, whose failure could not be reported, is declared only when it is
 not defined.

 @see "Exceptions", in the guide.
*/
#define WEBCPP_CRYPTO_NO_EXCEPTIONS
#undef WEBCPP_CRYPTO_NO_EXCEPTIONS
/** Defined on the WebAssembly targets, wasip2, wasip3 and Emscripten. */
#define WEBCPP_CRYPTO_WEBASSEMBLY 1
#undef WEBCPP_CRYPTO_WEBASSEMBLY
#endif

#if !defined(WEBCPP_HAS_EXCEPTIONS) && !defined(WEBCPP_CRYPTO_NO_EXCEPTIONS)
#define WEBCPP_CRYPTO_NO_EXCEPTIONS
#endif

#if defined(WEBCPP_TARGET_WASIP2) || defined(WEBCPP_TARGET_WASIP3) || \
    defined(WEBCPP_TARGET_EMSCRIPTEN)
#define WEBCPP_CRYPTO_WEBASSEMBLY 1
#endif

namespace webcpp::crypto::backends {

/** BearSSL, built from its sources by `/third_party//bearssl`. */
struct bearssl;
/** OpenSSL 3.5, built from its pinned sources, named by `/webcpp/crypto//openssl`. */
struct openssl;
/** ctaes as Bitcoin Core ships it, built from its source by `/third_party//ctaes`. */
struct ctaes;
/** libsecp256k1, built from its sources by `/third_party//secp256k1`. */
struct secp256k1;

}  // namespace webcpp::crypto::backends

#endif  // WEBCPP_CRYPTO_CONFIG_HPP
