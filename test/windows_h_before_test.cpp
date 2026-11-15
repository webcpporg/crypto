// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A bare <windows.h> (no NOMINMAX, no WIN32_LEAN_AND_MEAN) before every public header (spec
// sections 2.2 and 8.6), every backend's included (random_device's BCryptGenRandom reaches
// <windows.h> through detail/windows.hpp), and max used as a function after them. Elsewhere
// than Windows the program is the headers and the uses alone.
//
// The program calls max in parentheses: a bare <windows.h> included first defines the macros
// min and max for the whole program, which is what its author asked for and what webcpp's
// headers keep; their own (max)() is what is under test.
//
// OpenSSL after a bare <windows.h> (read, not run, in the headers of 3.5.9): the macros of
// wincrypt.h that name OpenSSL types are X509_NAME, X509_EXTENSIONS, PKCS7_SIGNER_INFO,
// OCSP_REQUEST and OCSP_RESPONSE (and X509_CERT_PAIR and PKCS7_ISSUER_AND_SERIAL, which
// x509.h and pkcs7.h use). include/openssl/types.h, the first header that names any of them,
// undefines the first five before its include guard and defines WINCRYPT_USE_SYMBOL_PREFIX for
// a <windows.h> that follows; the 29 headers backends/openssl.hpp reaches (evp.h, err.h and
// what they include) use no other name wincrypt.h defines, and include neither x509.h nor
// pkcs7.h. So nothing breaks; a bare <windows.h> first is what this program tests on MSVC.

#ifdef _WIN32
#include <windows.h>
#endif

#include <webcpp/crypto.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/config.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <limits>

// webcpp left defined none of the macros it defines for its own include of <windows.h>,
// which the program's include made add nothing.
#if defined(_WIN32) && (defined(NOMINMAX) || defined(WIN32_LEAN_AND_MEAN))
#error "webcpp's headers left NOMINMAX or WIN32_LEAN_AND_MEAN defined"
#endif

int main() {
    BOOST_TEST_EQ((std::max)(1, 2), 2);
    BOOST_TEST_EQ((webcpp::crypto::random_device::max)(),
                  (std::numeric_limits<unsigned int>::max)());
    BOOST_TEST_EQ((webcpp::crypto::random_device::min)(), 0U);
    return webcpp::test::exit_status(boost::report_errors());
}
