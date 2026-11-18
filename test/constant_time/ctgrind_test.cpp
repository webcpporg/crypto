// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Under Valgrind's memcheck, the key, the plaintext, the block and the tag are marked undefined:
// a branch or a memory index that depends on them is an error, and the run fails
// (--error-exitcode). It covers equal; make, seal and open of BearSSL's AES-GCM; make and seal
// of OpenSSL's; and make, encrypt and decrypt of ctaes's AES.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/equal.hpp>

#include <valgrind/memcheck.h>

#include <array>
#include <cstdint>
#include <cstdio>

namespace {

/** make, seal and open of BearSSL with the key, the data and the tag secret. */
int bearssl_seal_and_open() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    VALGRIND_MAKE_MEM_UNDEFINED(key.data(), key.size());
    VALGRIND_MAKE_MEM_UNDEFINED(data.data(), data.size());
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
    // The planted leak: a branch on a secret byte, which memcheck must report.
    if (key[0] == 0x42) {
        std::printf("planted\n");
    }
#endif
    auto made = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::make(key);
    auto tag = made->seal(iv, {}, data);
    VALGRIND_MAKE_MEM_UNDEFINED(tag->data(), tag->size());
    // The verdict is declassified inside the engine (WEBCPP_CRYPTO_DETAIL_DECLASSIFY).
    auto const opened = made->open(iv, {}, data, *tag);
    // And only because of that mark is the verdict defined: checked, since an optimiser may
    // turn the engine's branch on it into a select, which memcheck does not report.
    bool const verdict = opened.has_value();
    static_cast<void>(VALGRIND_CHECK_VALUE_IS_DEFINED(verdict));
    return verdict ? 0 : 1;
}

/**
 * make and seal of OpenSSL with the key and the data secret. Its open is not checked with
 * secrets: OpenSSL branches on the tag's verdict inside EVP_DecryptFinal_ex, where webcpp
 * cannot declassify it; the documentation says so.
 */
int openssl_seal() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    VALGRIND_MAKE_MEM_UNDEFINED(key.data(), key.size());
    VALGRIND_MAKE_MEM_UNDEFINED(data.data(), data.size());
    auto made = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>::make(key);
    auto const tag = made->seal(iv, {}, data);
    return tag ? 0 : 1;
}

/** make, encrypt and decrypt of ctaes with the key and the block secret. */
int ctaes_block() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> block{};
    key.fill(0x42);
    block.fill(0x17);
    VALGRIND_MAKE_MEM_UNDEFINED(key.data(), key.size());
    VALGRIND_MAKE_MEM_UNDEFINED(block.data(), block.size());
    auto made = crypto::ciphers::aes256<crypto::backends::ctaes>::make(key);
    bool const ok = made && made->encrypt(block) && made->decrypt(block);
    return ok ? 0 : 1;
}

}  // namespace

int main() {
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    VALGRIND_MAKE_MEM_UNDEFINED(a.data(), a.size());
    VALGRIND_MAKE_MEM_UNDEFINED(b.data(), b.size());
    bool equal = webcpp::crypto::equal(a, b);
    VALGRIND_MAKE_MEM_DEFINED(&equal, sizeof equal);  // the test's own branch below
    int const failures = (equal ? 0 : 1) + bearssl_seal_and_open() + openssl_seal() + ctaes_block();
    std::printf("constant time under memcheck: %s\n", failures == 0 ? "ok" : "FAILED");
    return failures;
}
