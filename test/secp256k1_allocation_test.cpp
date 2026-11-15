// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's one allocation (spec section 8.5): make allocates the signing context once, in
// the resource it is given, of libsecp256k1's preallocated size and aligned to max_align_t,
// and never through operator new nor the C library's allocator where the target lets a
// program count it; the signatures, ECDH, the public keys, both verifications, the DER and
// low-S functions and the x-only tweak allocate nothing, each counted alone; the destructor
// gives the block back; a refused make allocates nothing. A control proves the counter moves.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory_resource>
#include <span>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;

namespace {

// A resource of one block in a buffer of its own, which counts what it is asked: it calls no
// allocator, so that the counters see webcpp's allocations alone.
class counting_resource final : public std::pmr::memory_resource {
public:
    std::size_t allocated = 0;
    std::size_t deallocated = 0;
    std::size_t size = 0;
    std::size_t alignment = 0;

private:
    void* do_allocate(std::size_t bytes, std::size_t align) override {
        ++allocated;
        size = bytes;
        alignment = align;
        BOOST_TEST(bytes <= buffer_.size());
        return buffer_.data();
    }

    void do_deallocate(void* p, std::size_t bytes, std::size_t align) override {
        ++deallocated;
        BOOST_TEST(p == buffer_.data());
        BOOST_TEST_EQ(bytes, size);
        BOOST_TEST_EQ(align, alignment);
    }

    [[nodiscard]] bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override {
        return this == &other;
    }

    alignas(std::max_align_t) std::array<std::byte, 1024> buffer_{};
};

}  // namespace

int main() {
    std::cout << "the C library's allocations counted: " << webcpp::test::c_allocations_counted
              << "\n";
    // The control: one operator new moves the counter.
    std::size_t const control = webcpp::test::allocations();
    delete new int(1);  // NOLINT(cppcoreguidelines-owning-memory): the control's allocation
    BOOST_TEST(webcpp::test::allocations() > control);

    counting_resource resource;
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x42);
    std::array<std::uint8_t, 32> message{};
    message.fill(0x17);
    std::array<std::uint8_t, 32> const aux{};
    std::array<std::uint8_t, 32> const zero{};
    {
        std::size_t const before = webcpp::test::allocations();
        // A refused make allocates nothing, in the resource or elsewhere.
        BOOST_TEST(secp::keypair::make(zero, &resource).error() ==
                   crypto::error::invalid_secret_key);
        BOOST_TEST_EQ(resource.allocated, 0U);

        auto made = secp::keypair::make(secret, &resource);
        BOOST_TEST(made.has_value());
        BOOST_TEST_EQ(resource.allocated, 1U);
        BOOST_TEST_EQ(resource.size, secp256k1_context_preallocated_size(
                                         webcpp::crypto::detail::secp256k1_context_flags));
        BOOST_TEST_EQ(resource.alignment, alignof(std::max_align_t));
        secp::keypair key = std::move(*made);

        auto const schnorr = key.sign_schnorr(message, aux);
        auto const ecdsa = key.sign_ecdsa(message);
        auto const xonly = key.xonly_public_key();
        auto const public_key = key.public_key();
        auto const shared = key.ecdh(*public_key);
        BOOST_TEST(schnorr && ecdsa && xonly && public_key && shared);
        BOOST_TEST(secp::verify_schnorr(*schnorr, message, *xonly).has_value());
        BOOST_TEST(secp::verify_ecdsa(*ecdsa, message, *public_key).has_value());
        BOOST_TEST_EQ(webcpp::test::allocations(), before);

        // Each of the DER and low-S functions and the x-only tweak, alone: no allocation.
        auto const none = [](char const* name, auto&& call) {
            std::size_t const at = webcpp::test::allocations();
            bool const succeeded = static_cast<bool>(call());
            if (!succeeded || webcpp::test::allocations() != at) {
                BOOST_ERROR(name);
            }
        };
        std::array<std::uint8_t, secp::max_der_size> der{};
        std::size_t der_size = 0;
        none("to_der", [&] {
            auto const r = secp::to_der(*ecdsa, der);
            der_size = r ? *r : 0;
            return r;
        });
        auto const encoded = std::span<std::uint8_t const>(der).first(der_size);
        none("from_der", [&] { return secp::from_der(encoded); });
        none("normalize_ecdsa", [&] { return secp::normalize_ecdsa(*ecdsa); });
        none("tweak_xonly", [&] { return secp::tweak_xonly(*xonly, message); });
        none("keypair::tweak_xonly", [&] { return key.tweak_xonly(message); });
        BOOST_TEST_EQ(resource.allocated, 1U);
        BOOST_TEST_EQ(resource.deallocated, 0U);
    }
    // The destructor gave the block back, once.
    BOOST_TEST_EQ(resource.deallocated, 1U);
    return webcpp::test::exit_status(boost::report_errors());
}
