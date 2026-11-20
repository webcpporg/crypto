// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs BearSSL's code enters detail::timing_guard and leaves the
// thread's DIT as it found it, on every target, also where DIT does not apply: AES-128-GCM and
// AES-256-GCM, their moves included, and ChaCha20-Poly1305, each with valid input and with input
// refused before the backend (support/timing_coverage.hpp).

#include "support/timing_seam.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::bearssl;

// The ciphers: AES-GCM and ChaCha20-Poly1305.
void cover_ciphers() {
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes128<bearssl>>>("aes128_gcm",
                                                                                    "bearssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes256<bearssl>>>("aes256_gcm",
                                                                                    "bearssl");
    webcpp::test::cover_aead<crypto::ciphers::chacha20_poly1305<bearssl>>("chacha20_poly1305",
                                                                          "bearssl");
}

}  // namespace

int main() {
    cover_ciphers();
    return webcpp::test::exit_status(boost::report_errors());
}
