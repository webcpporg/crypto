// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// DIT after the adapter's catches (doc/memory.adoc): OpenSSL goes on after the adapter gives it
// null for a resource that throws, and after a `deallocate` that throws, inside the guarded call
// that reached it, so the adapter leaves DIT set where it was set. Windows on ARM64 clears DIT
// when it resumes a thread after a catch, which this test meets on the arm64 lane; elsewhere the
// resource clears DIT itself before it throws, which stands for that clear, so that the check
// fails on every CPU with DIT if the adapter does not set DIT again. Where DIT was clear the
// adapter leaves it clear. With exceptions alone: without them a resource cannot fail.

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/throw_exception.hpp>

#include <array>
#include <cstddef>
#include <memory_resource>
#include <new>
#include <stdexcept>

namespace {

/** How the test resource behaves on its next calls. */
enum class failure : unsigned char {
    /** It allocates and deallocates. */
    none,
    /** Its allocate throws. */
    allocate,
    /** Its deallocate throws, the block kept. */
    deallocate,
};

/**
 * Clears DIT where the CPU has it, as Windows on ARM64 does on resuming after a catch.
 */
void clear_dit() noexcept {
#ifdef WEBCPP_SECURE_TIMING_COVERED
    if (webcpp::secure::cpu_has_dit()) {
        webcpp::secure::detail::write_dit(0);
    }
#endif
}

class test_resource final : public std::pmr::memory_resource {
public:
    failure failing = failure::none;

private:
    void* do_allocate(std::size_t size, std::size_t alignment) override {
        if (failing == failure::allocate) {
            clear_dit();
            boost::throw_exception(std::bad_alloc());
        }
        return std::pmr::new_delete_resource()->allocate(size, alignment);
    }

    void do_deallocate(void* p, std::size_t size, std::size_t alignment) override {
        if (failing == failure::deallocate) {
            clear_dit();
            boost::throw_exception(std::runtime_error("deallocate fails"));
        }
        std::pmr::new_delete_resource()->deallocate(p, size, alignment);
    }

    [[nodiscard]] bool do_is_equal(memory_resource const& other) const noexcept override {
        return this == &other;
    }
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): never destroyed, by design
alignas(test_resource) std::array<unsigned char, sizeof(test_resource)> storage;

test_resource& the_resource() noexcept {
    static auto* const resource = new (storage.data()) test_resource;
    return *resource;
}

/**
 * A malloc, a realloc and a free whose resource throws, each followed by a check that DIT is
 * `expected`.
 *
 * @param expected DIT before the calls, and so after each.
 */
void check_catches(bool expected) {
    auto& resource = the_resource();
    resource.failing = failure::allocate;
    BOOST_TEST(webcpp_crypto_openssl_malloc(8, __FILE__, __LINE__) == nullptr);
    BOOST_TEST_EQ(webcpp::secure::dit_is_set(), expected);
    resource.failing = failure::none;

    void* const block = webcpp_crypto_openssl_malloc(8, __FILE__, __LINE__);
    if (!BOOST_TEST(block != nullptr)) {
        return;
    }
    resource.failing = failure::allocate;
    BOOST_TEST(webcpp_crypto_openssl_realloc(block, 64, __FILE__, __LINE__) == nullptr);
    BOOST_TEST_EQ(webcpp::secure::dit_is_set(), expected);

    resource.failing = failure::deallocate;
    webcpp_crypto_openssl_free(block, __FILE__, __LINE__);
    BOOST_TEST_EQ(webcpp::secure::dit_is_set(), expected);
    resource.failing = failure::none;
    webcpp_crypto_openssl_free(block, __FILE__, __LINE__);  // the block the throw kept
    BOOST_TEST_EQ(webcpp::secure::dit_is_set(), expected);
}

}  // namespace

std::pmr::memory_resource& webcpp::crypto::openssl_memory_resource() noexcept {
    return the_resource();
}

int main() {
    // Outside every guard, DIT clear: the adapter leaves it clear.
    BOOST_TEST(!webcpp::secure::dit_is_set());
    check_catches(false);
    BOOST_TEST(!webcpp::secure::dit_is_set());
    {
        // Inside a guard, as when OpenSSL runs inside from_key: set where the CPU has DIT, and
        // set again by the adapter after each catch.
        webcpp::secure::timing_guard const guard;
        bool const set = webcpp::secure::dit_is_set();
        BOOST_TEST_EQ(set, webcpp::secure::cpu_has_dit());
        check_catches(set);
    }
    BOOST_TEST(!webcpp::secure::dit_is_set());
    return webcpp::test::exit_status(boost::report_errors());
}
