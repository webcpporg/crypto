// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1::basic_keypair::generate with a planted source (the test seam
// WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY, a whole-program define, hence a program of its own): the
// source answers from a script of byte values, each filling a whole request, and fails once the
// script is spent. generate draws 32 bytes again when they are not a secret key (0xFF repeated
// is above the group order), at most four draws in all; the source failing, or four refusals,
// is entropy_unavailable; a failure allocates nothing; the one allocation of a success is the
// context's, from the resource given.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory_resource>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
std::vector<std::uint8_t> script;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's tally
std::size_t calls = 0;

// A resource that counts what it is asked, in a buffer of its own.
class counting_resource final : public std::pmr::memory_resource {
public:
    std::size_t allocated = 0;
    std::size_t deallocated = 0;
    std::size_t size = 0;

private:
    void* do_allocate(std::size_t bytes, std::size_t) override {
        ++allocated;
        size = bytes;
        BOOST_TEST(bytes <= buffer_.size());
        return buffer_.data();
    }

    void do_deallocate(void*, std::size_t, std::size_t) override { ++deallocated; }

    [[nodiscard]] bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override {
        return this == &other;
    }

    alignas(std::max_align_t) std::array<std::byte, 1024> buffer_{};
};

}  // namespace

extern "C" int webcpp_test_entropy(void* output_bytes, std::size_t byte_count) {
    ++calls;
    // As getentropy does: 0 when it fills, -1 with errno set when it fails.
    if (calls > script.size()) {
        errno = EIO;
        return -1;
    }
    std::memset(output_bytes, script[calls - 1], byte_count);
    return 0;
}

namespace {

void generate_redraws() {
    script = {0xFF, 0x01, 0x07};  // not a secret key, the secret key, the context's seed
    calls = 0;
    auto const generated = secp::keypair::generate();
    BOOST_TEST_EQ(calls, 3U);
    std::array<std::uint8_t, 32> expected_secret{};
    expected_secret.fill(0x01);
    script = {0x07};
    calls = 0;
    auto const expected = secp::keypair::make(expected_secret);
    if (BOOST_TEST(generated.has_value()) && BOOST_TEST(expected.has_value())) {
        BOOST_TEST(*generated->xonly_public_key() == *expected->xonly_public_key());
    }
}

void generate_four_refusals() {
    script = {0xFF, 0xFF, 0xFF, 0xFF};
    calls = 0;
    auto const generated = secp::keypair::generate();
    BOOST_TEST(!generated && generated.error() == crypto::error::entropy_unavailable);
    BOOST_TEST_EQ(calls, 4U);
}

void generate_source_fails() {
    script = {};
    calls = 0;
    counting_resource resource;
    auto const generated = secp::keypair::generate(&resource);
    BOOST_TEST(!generated && generated.error() == crypto::error::entropy_unavailable);
    BOOST_TEST_EQ(calls, 1U);
    BOOST_TEST_EQ(resource.allocated, 0U);
}

void generate_resource() {
    script = {0x01, 0x07};
    calls = 0;
    counting_resource resource;
    {
        auto const generated = secp::keypair::generate(&resource);
        BOOST_TEST(generated.has_value());
        BOOST_TEST_EQ(resource.allocated, 1U);
        BOOST_TEST_EQ(resource.size, secp256k1_context_preallocated_size(
                                         webcpp::crypto::detail::secp256k1_context_flags));
    }
    BOOST_TEST_EQ(resource.deallocated, 1U);
}

}  // namespace

int main() {
    generate_redraws();
    generate_four_refusals();
    generate_source_fails();
    generate_resource();
    return webcpp::test::exit_status(boost::report_errors());
}
