// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 key pair's secret key and an Ed25519ph signer's SHA-512 state are zero in their
// storage once moved from, once moved over, once the message is ended (the signer) and once
// destroyed, read at -O2 with every call inlined (the Jamfile's requirements), where a wipe the
// optimiser may drop as a dead store would be dropped. Each object's state is its first member,
// at the start of its storage: the classes are standard-layout, which the test asserts.

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;

using ed25519::keypair;
using signer = ed25519::ph<webcpp::hash::sha2_512>;
constexpr std::size_t keypair_state =
    sizeof(crypto::detail::ed25519_state<crypto::families::ed25519, crypto::backends::sodium>);
constexpr std::size_t signer_state =
    sizeof(crypto::detail::ed25519ph_state<crypto::tags::ed25519ph, crypto::backends::sodium>);

static_assert(std::is_standard_layout_v<keypair> && std::is_standard_layout_v<signer>);
static_assert(keypair_state == 64 && signer_state <= sizeof(signer));

// A function the optimiser cannot see into, so that what it is handed is read from memory.
#if defined(_MSC_VER) && !defined(__clang__)
#define WEBCPP_TEST_NOINLINE __declspec(noinline)
#else
#define WEBCPP_TEST_NOINLINE __attribute__((noinline))
#endif

// Whether every byte at `where` is zero, read through a volatile pointer in a function that is
// never inlined. It may be handed the storage of an object that is gone (the destructor's
// check), so it is exempt from the sanitizers that would stop that read.
#if defined(__clang__) || defined(__GNUC__)
__attribute__((no_sanitize("address")))
#endif
WEBCPP_TEST_NOINLINE bool memory_is_zero(void const* where, std::size_t count) {
    auto const volatile* const bytes = static_cast<unsigned char const volatile*>(where);
    for (std::size_t i = 0; i < count; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

// RFC 8032 section 7.3's seed, and its message "abc".
constexpr std::array<std::uint8_t, 32> seed{
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
};
constexpr std::array<std::uint8_t, 3> abc{0x61, 0x62, 0x63};

void key_pairs() {
    auto made = keypair::make(seed);
    BOOST_TEST(made.has_value());
    if (!made) {
        return;
    }
    // Alive, the state holds the secret key: the checks below can fail.
    BOOST_TEST(!memory_is_zero(&*made, keypair_state));

    keypair taken = std::move(*made);
    BOOST_TEST(memory_is_zero(&*made, keypair_state));

    auto other = keypair::make(seed);
    BOOST_TEST(other.has_value());
    if (other) {
        taken = std::move(*other);
        BOOST_TEST(memory_is_zero(&*other, keypair_state));
    }

    // Destroyed in storage this frame owns: its bytes are read after the destructor.
    alignas(keypair) std::array<std::byte, sizeof(keypair)> storage{};
    keypair* const placed =
        std::construct_at(reinterpret_cast<keypair*>(storage.data()), std::move(taken));
    BOOST_TEST(!memory_is_zero(placed, keypair_state));
    std::destroy_at(placed);
    BOOST_TEST(memory_is_zero(storage.data(), keypair_state));
}

void signers() {
    auto const key = keypair::make(seed);
    auto begun = signer::begin();
    BOOST_TEST(key.has_value() && begun.has_value());
    if (!key || !begun) {
        return;
    }
    BOOST_TEST(begun->update(abc).has_value());
    BOOST_TEST(!memory_is_zero(&*begun, signer_state));

    signer moved = std::move(*begun);
    BOOST_TEST(memory_is_zero(&*begun, signer_state));

    // Signed, the message is ended and its state wiped.
    BOOST_TEST(moved.sign(*key).has_value());
    BOOST_TEST(memory_is_zero(&moved, signer_state));

    auto other = signer::begin();
    BOOST_TEST(other.has_value());
    if (!other) {
        return;
    }
    BOOST_TEST(other->update(abc).has_value());
    moved = std::move(*other);
    BOOST_TEST(memory_is_zero(&*other, signer_state));

    alignas(signer) std::array<std::byte, sizeof(signer)> storage{};
    signer* const placed =
        std::construct_at(reinterpret_cast<signer*>(storage.data()), std::move(moved));
    BOOST_TEST(!memory_is_zero(placed, signer_state));
    std::destroy_at(placed);
    BOOST_TEST(memory_is_zero(storage.data(), signer_state));
}

}  // namespace

int main() {
    key_pairs();
    signers();
    return webcpp::test::exit_status(boost::report_errors());
}
