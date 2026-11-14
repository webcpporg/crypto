// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_SRC_OPENSSL_ON_EMSCRIPTEN_HPP
#define WEBCPP_CRYPTO_SRC_OPENSSL_ON_EMSCRIPTEN_HPP

// Forced into every source when an Emscripten program names /webcpp/crypto//openssl.
#if defined(__EMSCRIPTEN__)
#error \
    "webcpp::crypto: /webcpp/crypto//openssl is named in a build for Emscripten, where webcpp does not build OpenSSL. In the program's Jamfile, replace /webcpp/crypto//openssl with /third_party//bearssl, or name OpenSSL for native and WASI builds alone, by a condition in the project's requirements: project : requirements <conditional>@native-openssl ; rule native-openssl ( properties * ) { if ! <toolset>emscripten in $(properties) { return <library>/webcpp/crypto//openssl ; } } (without b2: link OpenSSL into native and WASI programs only)"
#endif
#endif  // WEBCPP_CRYPTO_SRC_OPENSSL_ON_EMSCRIPTEN_HPP
