// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On OpenSSL a message allocates nothing (spec section 8.5): after from_key, which allocates
// through OpenSSL's functions (counted here and printed, not refused), seal, open (good and
// failed), the incremental seal, encrypt and decrypt, and ChaCha20-Poly1305's seal and open
// (good and failed) make no call of OpenSSL's allocator, of
// operator new, nor of the C library's allocator where the target lets a program count it.
// OpenSSL's allocations are outside the user's allocator (the accepted departure); its count
// is measured per target on OpenSSL 3.5.9 (native with assembly; MSVC, wasip2 and wasip3
// without it).

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"
#include "support/gcm_checks.hpp"

#include <openssl/crypto.h>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): OpenSSL's allocation count
std::atomic<std::size_t> openssl_allocations{0};

#ifdef __GLIBC__
// __libc_malloc, __libc_realloc and __libc_free are declared by support/counting.hpp.
#define WEBCPP_TEST_OPENSSL_C(name) __libc_##name
#else
#define WEBCPP_TEST_OPENSSL_C(name) std::name
#endif

void* counting_malloc(std::size_t size, char const* /*file*/, int /*line*/) {
    ++openssl_allocations;
    return WEBCPP_TEST_OPENSSL_C(malloc)(size);
}

void* counting_realloc(void* p, std::size_t size, char const* /*file*/, int /*line*/) {
    ++openssl_allocations;
    return WEBCPP_TEST_OPENSSL_C(realloc)(p, size);
}

void counting_free(void* p, char const* /*file*/, int /*line*/) {
    WEBCPP_TEST_OPENSSL_C(free)(p);
}

}  // namespace

int main() {
    namespace crypto = webcpp::crypto;
    // Before anything: OpenSSL allocates through the test's functions from here on.
    BOOST_TEST(CRYPTO_set_mem_functions(&counting_malloc, &counting_realloc, &counting_free) == 1);
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 4096> data{};
    std::array<std::uint8_t, 16> block{};

    std::size_t const first = openssl_allocations.load();
    auto made =
        crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>::from_key(key);
    std::size_t const made_count = openssl_allocations.load() - first;
    BOOST_TEST(made.has_value());
    std::printf("from_key: %zu allocations through OpenSSL's functions, first from_key included\n",
                made_count);
    std::size_t const second_first = openssl_allocations.load();
    auto second = crypto::ciphers::aes256<crypto::backends::openssl>::from_key(key);
    std::size_t const second_count = openssl_allocations.load() - second_first;
    BOOST_TEST(second.has_value());
    std::printf("second from_key: %zu\n", second_count);
    std::size_t const chacha_first = openssl_allocations.load();
    auto chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::openssl>::from_key(key);
    std::size_t const chacha_count = openssl_allocations.load() - chacha_first;
    BOOST_TEST(chacha.has_value());
    std::printf("ChaCha20-Poly1305's from_key: %zu\n", chacha_count);
    if (!made.has_value() || !second.has_value() || !chacha.has_value()) {
        return webcpp::test::exit_status(boost::report_errors());
    }

    std::size_t const own_before = openssl_allocations.load();
    std::size_t const before = webcpp::test::allocations();
    auto const tag = made->seal(nonce, {}, data);
    bool const sealed = tag.has_value();
    bool const opened = sealed && made->open(nonce, {}, data, *tag).has_value();
    std::array<std::uint8_t, 16> wrong{};
    bool const refused = !made->open(nonce, {}, data, wrong).has_value();
    bool const begun = made->begin_seal(nonce, {}).has_value();
    bool const updated = made->update(data).has_value();
    bool const resulted = made->result().has_value();
    // The two-pass open; verify restarts the OpenSSL context with EVP_CipherInit_ex.
    auto const open_tag = made->seal(nonce, {}, data);
    bool const two_pass = open_tag.has_value() && made->begin_open(nonce, {}).has_value() &&
                          made->authenticate(data).has_value() &&
                          made->verify(*open_tag).has_value() && made->decrypt(data).has_value() &&
                          made->end_open().has_value();
    bool const encrypted = second->encrypt(block).has_value();
    bool const decrypted = second->decrypt(block).has_value();
    auto const chacha_tag = chacha->seal(nonce, nonce, data);
    bool const chacha_sealed = chacha_tag.has_value();
    bool const chacha_opened =
        chacha_sealed && chacha->open(nonce, nonce, data, *chacha_tag).has_value();
    bool const chacha_refused = !chacha->open(nonce, nonce, data, wrong).has_value();
    std::size_t const after = webcpp::test::allocations();
    std::size_t const own_after = openssl_allocations.load();
    BOOST_TEST(sealed);
    BOOST_TEST(opened);
    BOOST_TEST(refused);
    BOOST_TEST(begun);
    BOOST_TEST(updated);
    BOOST_TEST(resulted);
    BOOST_TEST(two_pass);
    BOOST_TEST(encrypted);
    BOOST_TEST(decrypted);
    BOOST_TEST(chacha_sealed);
    BOOST_TEST(chacha_opened);
    BOOST_TEST(chacha_refused);
    BOOST_TEST_EQ(own_after, own_before);
    BOOST_TEST_EQ(after, before);
    return webcpp::test::exit_status(boost::report_errors());
}
