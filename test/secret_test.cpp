// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secret<N> is not copyable, clone copies by name, a move leaves the source zero, it converts to
// a span of fixed size, and its storage is zero after its destructor, read at -O2 (the Jamfile's
// <optimization>speed), where a store the optimiser may drop is the case.

#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;

using key = crypto::secret<32>;

static_assert(!std::is_copy_constructible_v<key>);
static_assert(!std::is_copy_assignable_v<key>);
static_assert(std::is_nothrow_move_constructible_v<key>);
static_assert(std::is_nothrow_move_assignable_v<key>);
static_assert(std::is_convertible_v<key const&, std::span<std::uint8_t const, 32>>);
static_assert(key::size() == 32 && key::size_bytes == 32);
static_assert(sizeof(key) == 32);

void fill(key& target, std::uint8_t first) {
    auto const bytes = target.writable();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(first + i);
    }
}

bool is_zero(key const& source) {
    for (std::uint8_t const byte : source.bytes()) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

// Whether any byte of the storage is not zero, read through a volatile pointer.
bool any_set(std::array<std::byte, sizeof(key)> const& storage) {
    auto const* const bytes = reinterpret_cast<unsigned char const volatile*>(storage.data());
    for (std::size_t i = 0; i < storage.size(); ++i) {
        if (bytes[i] != 0) {
            return true;
        }
    }
    return false;
}

}  // namespace

int main() {
    // A new secret is zero.
    key const zero;
    BOOST_TEST(is_zero(zero));

    // clone copies, and the two are then independent.
    key original;
    fill(original, 1);
    key copy = original.clone();
    BOOST_TEST(!is_zero(original));
    BOOST_TEST(std::equal(copy.bytes().begin(), copy.bytes().end(), original.bytes().begin()));
    copy.writable()[0] = 0xee;
    BOOST_TEST_EQ(original.bytes()[0], 1);

    // A move construction leaves the source zero and the destination with the bytes.
    key from;
    fill(from, 7);
    key const expected = from.clone();
    key to(std::move(from));
    BOOST_TEST(is_zero(from));
    BOOST_TEST(std::equal(to.bytes().begin(), to.bytes().end(), expected.bytes().begin()));

    // A move assignment does too, over the destination's own bytes.
    key assigned;
    fill(assigned, 100);
    key source;
    fill(source, 7);
    assigned = std::move(source);
    BOOST_TEST(is_zero(source));
    BOOST_TEST(
        std::equal(assigned.bytes().begin(), assigned.bytes().end(), expected.bytes().begin()));

    // The conversion to a span of fixed size views the same bytes.
    std::span<std::uint8_t const, 32> const view = expected;
    BOOST_TEST(view.data() == expected.bytes().data());
    BOOST_TEST_EQ(view.size(), 32u);

    // After the destructor, the storage is zero.
    alignas(key) std::array<std::byte, sizeof(key)> storage{};
    auto* const placed = new (storage.data()) key;
    fill(*placed, 1);
    BOOST_TEST(any_set(storage));
    std::destroy_at(placed);
    BOOST_TEST(!any_set(storage));

    return webcpp::test::exit_status(boost::report_errors());
}
