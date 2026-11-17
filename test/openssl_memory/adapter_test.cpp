// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The adapter's C functions, called directly (spec section 3.7): 0 bytes and a size whose
// header overflows give null without asking the resource; a block is aligned as malloc's;
// realloc grows, shrinks, frees at 0 and, when the resource fails, returns null and
// leaves the old block valid; a resource that throws (with exceptions) or returns null
// (without) is a null for OpenSSL.

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/throw_exception.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory_resource>
#include <new>

namespace {

class test_resource final : public std::pmr::memory_resource {
public:
    std::size_t allocations = 0;
    std::size_t live = 0;
    bool failing = false;

private:
    void* do_allocate(std::size_t size, std::size_t alignment) override {
        if (failing) {
#ifdef WEBCPP_CRYPTO_NO_EXCEPTIONS
            return nullptr;
#else
            boost::throw_exception(std::bad_alloc());
#endif
        }
        ++allocations;
        ++live;
        return std::pmr::new_delete_resource()->allocate(size, alignment);
    }

    void do_deallocate(void* p, std::size_t size, std::size_t alignment) override {
        --live;
        std::pmr::new_delete_resource()->deallocate(p, size, alignment);
    }

    bool do_is_equal(memory_resource const& other) const noexcept override {
        return this == &other;
    }
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): never destroyed, by design
alignas(test_resource) std::array<unsigned char, sizeof(test_resource)> storage;

test_resource& the_resource() noexcept {
    static auto* const resource = new (storage.data()) test_resource;
    return *resource;
}

}  // namespace

std::pmr::memory_resource& webcpp::crypto::openssl_memory_resource() noexcept {
    return the_resource();
}

int main() {
    namespace detail = webcpp::crypto::detail;
    auto& resource = the_resource();
    BOOST_TEST(webcpp_crypto_openssl_malloc(0, __FILE__, __LINE__) == nullptr);
    BOOST_TEST(webcpp_crypto_openssl_malloc((std::numeric_limits<std::size_t>::max)() - 3, __FILE__,
                                            __LINE__) == nullptr);
    BOOST_TEST_EQ(resource.allocations, 0U);

    void* const block = webcpp_crypto_openssl_malloc(10, __FILE__, __LINE__);
    BOOST_TEST(block != nullptr);
    BOOST_TEST_EQ(reinterpret_cast<std::uintptr_t>(block) % detail::openssl_block_alignment, 0U);
    std::memcpy(block, "0123456789", 10);

    void* const grown = webcpp_crypto_openssl_realloc(block, 1000, __FILE__, __LINE__);
    BOOST_TEST(grown != nullptr && std::memcmp(grown, "0123456789", 10) == 0);
    void* const shrunk = webcpp_crypto_openssl_realloc(grown, 4, __FILE__, __LINE__);
    BOOST_TEST(shrunk != nullptr && std::memcmp(shrunk, "0123", 4) == 0);

    resource.failing = true;
    BOOST_TEST(webcpp_crypto_openssl_malloc(8, __FILE__, __LINE__) == nullptr);
    BOOST_TEST(webcpp_crypto_openssl_realloc(shrunk, 64, __FILE__, __LINE__) == nullptr);
    BOOST_TEST(std::memcmp(shrunk, "0123", 4) == 0);  // the old block is still valid
    resource.failing = false;

    BOOST_TEST(webcpp_crypto_openssl_realloc(shrunk, 0, __FILE__, __LINE__) == nullptr);
    BOOST_TEST_EQ(resource.live, 0U);
    void* const fresh = webcpp_crypto_openssl_realloc(nullptr, 16, __FILE__, __LINE__);
    BOOST_TEST(fresh != nullptr);
    webcpp_crypto_openssl_free(fresh, __FILE__, __LINE__);
    webcpp_crypto_openssl_free(nullptr, __FILE__, __LINE__);
    BOOST_TEST_EQ(resource.live, 0U);
    return webcpp::test::exit_status(boost::report_errors());
}
