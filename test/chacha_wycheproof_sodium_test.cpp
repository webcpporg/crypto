// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ChaCha20-Poly1305 and XChaCha20-Poly1305 on libsodium against Wycheproof's vectors, read at
// run time from third_party/libs/wycheproof (support/wycheproof_aead.hpp): of
// chacha20_poly1305_test.json's 325 tests, 256 valid, 60 invalid and 9 with a nonce of
// another size than 12 bytes; of xchacha20_poly1305_test.json's 315, 246 valid, 60 invalid
// and 9 with a nonce of another size than 24 bytes.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/wycheproof_aead.hpp"

#include <boost/core/lightweight_test.hpp>

int main() {
    namespace ciphers = webcpp::crypto::ciphers;
    using webcpp::crypto::backends::sodium;
    webcpp::test::check_wycheproof_aead<ciphers::chacha20_poly1305<sodium>>(
        "chacha20_poly1305_test.json", {.valid = 256, .invalid = 60, .other_iv = 9});
    webcpp::test::check_wycheproof_aead<ciphers::xchacha20_poly1305<sodium>>(
        "xchacha20_poly1305_test.json", {.valid = 246, .invalid = 60, .other_iv = 9});
    return webcpp::test::exit_status(boost::report_errors());
}
