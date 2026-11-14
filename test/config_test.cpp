// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto/config.hpp> defines WEBCPP_CRYPTO_NO_EXCEPTIONS exactly when
// webcpp has no exceptions, keeps the developer's own definition in a build that
// has them, and defines WEBCPP_CRYPTO_WEBASSEMBLY exactly on wasip2, wasip3 and
// Emscripten. test/Jamfile builds this file as the build asks; without exceptions;
// with WEBCPP_NO_EXCEPTIONS defined as a developer defines it for every webcpp
// library, which WEBCPP_TEST_CRYPTO_ALL_OFF tells this file; and with the macro
// itself defined on the command line, which WEBCPP_TEST_CRYPTO_DEVELOPER_DEFINED
// tells this file.

#include <webcpp/crypto/config.hpp>

// webcpp's configuration, which config.hpp includes, has said whether webcpp
// has exceptions and which target the program is for.
#ifndef WEBCPP_CONFIG_HPP
#error "config.hpp does not include <webcpp/config.hpp>"
#endif

#ifdef WEBCPP_TEST_CRYPTO_ALL_OFF
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
#error "WEBCPP_NO_EXCEPTIONS does not define WEBCPP_CRYPTO_NO_EXCEPTIONS"
#endif
#elif defined(WEBCPP_TEST_CRYPTO_DEVELOPER_DEFINED)
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
#error "config.hpp drops WEBCPP_CRYPTO_NO_EXCEPTIONS, which the developer defined"
#endif
#elif defined(WEBCPP_HAS_EXCEPTIONS) == defined(WEBCPP_CRYPTO_NO_EXCEPTIONS)
#error "WEBCPP_CRYPTO_NO_EXCEPTIONS is not defined exactly when webcpp has no exceptions"
#endif

#if defined(WEBCPP_TARGET_NATIVE) == defined(WEBCPP_CRYPTO_WEBASSEMBLY)
#error "WEBCPP_CRYPTO_WEBASSEMBLY is not defined exactly on WebAssembly"
#endif
