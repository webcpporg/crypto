// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs OpenSSL's code enters its own detail::timing_guard and leaves
// the thread's DIT as it found it, on native, wasip2 and wasip3, also where DIT does not apply,
// each with valid input and with input refused before the backend (support/timing_coverage.hpp).
// A check fails, naming itself, when its call enters no guard or when the first guard it enters is
// not the one of the function it names (support/timing_seam.hpp), so that a function that forgot
// its own guard fails although it calls another guarded function.
//
// What it covers, by family; a family OpenSSL gains adds its line and its checks:
// - The AES block cipher, aes128, aes192 and aes256: make; basic_aes: encrypt, decrypt.
// - AES-GCM, gcm<aes128>, gcm<aes192> and gcm<aes256>: make, the move constructor and move
//   assignment (ruling R3), seal, open, begin_seal, update, result, and the asynchronous
//   async_make, async_seal and async_open, free and member; the free crypto::make, crypto::seal
//   and crypto::open.
// - ChaCha20-Poly1305, aead: make, seal, open; the free crypto::make, crypto::seal and
//   crypto::open.

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
    webcpp::test::cover_async_gcm<crypto::ciphers::gcm<crypto::ciphers::aes128<openssl>>>(
        "aes128_gcm", "openssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes192<openssl>>>("aes192_gcm",
                                                                                    "openssl");
    webcpp::test::cover_async_gcm<crypto::ciphers::gcm<crypto::ciphers::aes192<openssl>>>(
        "aes192_gcm", "openssl");
    webcpp::test::cover_gcm<crypto::ciphers::gcm<crypto::ciphers::aes256<openssl>>>("aes256_gcm",
                                                                                    "openssl");
    webcpp::test::cover_async_gcm<crypto::ciphers::gcm<crypto::ciphers::aes256<openssl>>>(
        "aes256_gcm", "openssl");
    webcpp::test::cover_aead<crypto::ciphers::chacha20_poly1305<openssl>>("chacha20_poly1305",
                                                                          "openssl");
}

}  // namespace

int main() {
    cover_ciphers();
    return webcpp::test::exit_status(boost::report_errors());
}
