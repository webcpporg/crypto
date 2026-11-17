// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto/config.hpp> defines WEBCPP_CRYPTO_HAS_THREADS by design D23's rule: natively
// exactly when Boost.Config defines BOOST_HAS_THREADS, on Emscripten exactly with -pthread, never
// on wasip2 or wasip3, and never when the program defines WEBCPP_CRYPTO_NO_THREADS. test/Jamfile
// builds this file natively with b2's threading=single (WEBCPP_TEST_CRYPTO_THREADING_SINGLE),
// with threading=multi (WEBCPP_TEST_CRYPTO_THREADING_MULTI), and with threading=multi and
// WEBCPP_CRYPTO_NO_THREADS; and on wasip2, wasip3 and Emscripten without -pthread. The
// Emscripten build with -pthread is the fixture threads_on_emscripten of
// tools/test/crypto_jamfiles_test.py.
//
// threading=single does not take BOOST_HAS_THREADS away: Boost.Config (1.92) defines it on macOS
// (__APPLE__, boost/config/detail/suffix.hpp), on MSVC (_MT), with libstdc++ where it has gthreads
// (boost/config/stdlib/libstdcpp3.hpp) and with libc++ always (boost/config/stdlib/libcpp.hpp), so
// that a native build without WEBCPP_CRYPTO_NO_THREADS has threads; the single build checks the
// rule against Boost.Config's macro, whatever it says on the machine.

#include <webcpp/crypto/config.hpp>

#if defined(WEBCPP_TARGET_WASIP2) || defined(WEBCPP_TARGET_WASIP3)
#ifdef WEBCPP_CRYPTO_HAS_THREADS
#error "WEBCPP_CRYPTO_HAS_THREADS is defined on WASI"
#endif
#elif defined(WEBCPP_TARGET_EMSCRIPTEN)
#if defined(WEBCPP_CRYPTO_HAS_THREADS) != defined(__EMSCRIPTEN_PTHREADS__)
#error "WEBCPP_CRYPTO_HAS_THREADS is not defined exactly with -pthread on Emscripten"
#endif
#elif defined(WEBCPP_CRYPTO_NO_THREADS)
#ifdef WEBCPP_CRYPTO_HAS_THREADS
#error "WEBCPP_CRYPTO_HAS_THREADS is defined though the program defines WEBCPP_CRYPTO_NO_THREADS"
#endif
#elif defined(WEBCPP_TEST_CRYPTO_THREADING_MULTI)
#ifndef WEBCPP_CRYPTO_HAS_THREADS
#error "WEBCPP_CRYPTO_HAS_THREADS is not defined with threading=multi"
#endif
#elif defined(WEBCPP_TEST_CRYPTO_THREADING_SINGLE)
#if defined(WEBCPP_CRYPTO_HAS_THREADS) != defined(BOOST_HAS_THREADS)
#error "WEBCPP_CRYPTO_HAS_THREADS is not defined exactly when BOOST_HAS_THREADS is"
#endif
#else
#error "test/Jamfile builds this file natively with one of the threading cases"
#endif

int main() {}
