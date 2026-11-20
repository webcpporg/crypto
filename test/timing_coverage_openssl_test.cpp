// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs OpenSSL's code enters detail::timing_guard and leaves the
// thread's DIT as it found it, on native, wasip2 and wasip3, also where DIT does not apply: the
// AES block cipher of each key size, AES-128-GCM and AES-256-GCM, their moves included, and
// ChaCha20-Poly1305, each with valid input and with input refused before the backend
// (support/timing_coverage.hpp).

#include "support/timing_seam.hpp"

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::openssl;

// The ciphers: the AES block cipher, AES-GCM and ChaCha20-Poly1305.
void cover_ciphers() {
    webcpp::test::cover_aes<crypto::ciphers::aes128<openssl>>("aes128", "openssl");
    webcpp::test::cover_aes<crypto::ciphers::aes192<openssl>>("aes192", "openssl");
    webcpp::test::cover_aes<crypto::ciphers::aes256<openssl>>("aes256", "openssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes128<openssl>>>("aes128_gcm",
                                                                                    "openssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes256<openssl>>>("aes256_gcm",
                                                                                    "openssl");
    webcpp::test::cover_aead<crypto::ciphers::chacha20_poly1305<openssl>>("chacha20_poly1305",
                                                                          "openssl");
}

}  // namespace

int main() {
    cover_ciphers();
    return webcpp::test::exit_status(boost::report_errors());
}
