// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On OpenSSL a message allocates nothing (spec section 8.5): after make, which allocates
// through OpenSSL's functions (counted here and printed, not refused), seal, open (good and
// failed), the incremental seal, encrypt and decrypt make no call of OpenSSL's allocator, of
// operator new, nor of the C library's allocator where the target lets a program count it.
// OpenSSL's allocations are outside the user's allocator (the accepted departure); its count
// is measured per target on OpenSSL 3.5.9 (native with assembly; MSVC, wasip2 and wasip3
// without it).

#include <webcpp/crypto/backends/openssl.hpp>
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

#if defined(__GLIBC__)
// __libc_malloc, __libc_realloc and __libc_free are declared by support/counting.hpp.
#define WEBCPP_TEST_OPENSSL_C(name) __libc_##name
#else
#define WEBCPP_TEST_OPENSSL_C(name) std::name
#endif

void* counting_malloc(std::size_t size, char const*, int) {
    ++openssl_allocations;
    return WEBCPP_TEST_OPENSSL_C(malloc)(size);
}

void* counting_realloc(void* p, std::size_t size, char const*, int) {
    ++openssl_allocations;
    return WEBCPP_TEST_OPENSSL_C(realloc)(p, size);
}

void counting_free(void* p, char const*, int) {
    WEBCPP_TEST_OPENSSL_C(free)(p);
}

}  // namespace

int main() {
    namespace crypto = webcpp::crypto;
    // Before anything: OpenSSL allocates through the test's functions from here on.
    BOOST_TEST(CRYPTO_set_mem_functions(&counting_malloc, &counting_realloc, &counting_free) == 1);
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> iv{};
    std::array<std::uint8_t, 4096> data{};
    std::array<std::uint8_t, 16> block{};

    std::size_t const first = openssl_allocations.load();
    auto made = crypto::gcm<crypto::aes256<crypto::backends::openssl>>::make(key);
    std::size_t const made_count = openssl_allocations.load() - first;
    BOOST_TEST(made.has_value());
    std::printf("make: %zu allocations through OpenSSL's functions, first make included\n",
                made_count);
    std::size_t const second_first = openssl_allocations.load();
    auto second = crypto::aes256<crypto::backends::openssl>::make(key);
    std::size_t const second_count = openssl_allocations.load() - second_first;
    BOOST_TEST(second.has_value());
    std::printf("second make: %zu\n", second_count);
    if (!made.has_value() || !second.has_value()) {
        return webcpp::test::exit_status(boost::report_errors());
    }

    std::size_t const own_before = openssl_allocations.load();
    std::size_t const before = webcpp::test::allocations();
    auto const tag = made->seal(iv, {}, data);
    bool const sealed = tag.has_value();
    bool const opened = sealed && made->open(iv, {}, data, *tag).has_value();
    std::array<std::uint8_t, 16> wrong{};
    bool const refused = !made->open(iv, {}, data, wrong).has_value();
    bool const begun = made->begin_seal(iv, {}).has_value();
    bool const updated = made->update(data).has_value();
    bool const resulted = made->result().has_value();
    bool const encrypted = second->encrypt(block).has_value();
    bool const decrypted = second->decrypt(block).has_value();
    std::size_t const after = webcpp::test::allocations();
    std::size_t const own_after = openssl_allocations.load();
    BOOST_TEST(sealed);
    BOOST_TEST(opened);
    BOOST_TEST(refused);
    BOOST_TEST(begun);
    BOOST_TEST(updated);
    BOOST_TEST(resulted);
    BOOST_TEST(encrypted);
    BOOST_TEST(decrypted);
    BOOST_TEST_EQ(own_after, own_before);
    BOOST_TEST_EQ(after, before);
    return webcpp::test::exit_status(boost::report_errors());
}
