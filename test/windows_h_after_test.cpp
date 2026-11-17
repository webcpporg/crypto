// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public header (spec sections 2.2 and 8.6), every backend's included, then a bare
// <windows.h> (no NOMINMAX, no WIN32_LEAN_AND_MEAN), and max called as a function after them,
// without parentheses. It compiles because webcpp's own include of <windows.h> defined
// NOMINMAX and WIN32_LEAN_AND_MEAN and undefined them after, and <windows.h>'s include guard
// makes the program's include add nothing. Elsewhere than Windows the program is the headers
// and the uses alone.

#include <webcpp/crypto.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/config.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>
#include <webcpp/crypto/curves/secp256k1/formats.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/test/exit_status.hpp>

// webcpp undefined again the macros it defined for its own include.
#if defined(_WIN32) && (defined(NOMINMAX) || defined(WIN32_LEAN_AND_MEAN))
#error "webcpp's headers left NOMINMAX or WIN32_LEAN_AND_MEAN defined"
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <limits>
#include <memory_resource>

// With WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE (test/openssl_memory's twins, spec section 8.6), the
// option's branch of backends/openssl.hpp is compiled too, and the program defines the resource
// the option needs.
#ifdef WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE
std::pmr::memory_resource& webcpp::crypto::openssl_memory_resource() noexcept {
    return *std::pmr::new_delete_resource();
}
#endif

int main() {
    BOOST_TEST_EQ(std::max(1, 2), 2);
    BOOST_TEST_EQ(webcpp::crypto::random_device::max(), std::numeric_limits<unsigned int>::max());
    BOOST_TEST_EQ(webcpp::crypto::random_device::min(), 0U);
    return webcpp::test::exit_status(boost::report_errors());
}
