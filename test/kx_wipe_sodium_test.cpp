// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A crypto_kx key pair's secret key is zero in its storage once moved from, once moved over and
// once destroyed, read at -O2 with every call inlined (the Jamfile's requirements), where a wipe
// the optimiser may drop as a dead store would be dropped. The secret key is the first member of
// the key pair's state, itself the key pair's first member, at the start of its storage: the
// classes are standard-layout, which the test asserts.

#include <webcpp/crypto/curves/x25519/kx.hpp>
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
namespace x25519 = webcpp::crypto::curves::x25519;

using x25519::kx_keypair;
using state = crypto::detail::kx_state<crypto::families::kx, crypto::backends::sodium>;

// The secret key's bytes, at the start of the state.
constexpr std::size_t secret_key_size = sizeof(state::secret_key);

static_assert(std::is_standard_layout_v<kx_keypair<>> && std::is_standard_layout_v<state>);
static_assert(secret_key_size == 32 && offsetof(state, secret_key) == 0);

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

// libsodium's kx.c seed, the bytes 0 to 31.
constexpr std::array<std::uint8_t, 32> seed{
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

void key_pairs() {
    auto made = kx_keypair<>::make(seed);
    BOOST_TEST(made.has_value());
    if (!made) {
        return;
    }
    // Alive, the state holds the secret key: the checks below can fail.
    BOOST_TEST(!memory_is_zero(&*made, secret_key_size));

    kx_keypair<> taken = std::move(*made);
    BOOST_TEST(memory_is_zero(&*made, secret_key_size));

    auto other = kx_keypair<>::make(seed);
    BOOST_TEST(other.has_value());
    if (other) {
        taken = std::move(*other);
        BOOST_TEST(memory_is_zero(&*other, secret_key_size));
    }

    // Destroyed in storage this frame owns: its bytes are read after the destructor.
    alignas(kx_keypair<>) std::array<std::byte, sizeof(kx_keypair<>)> storage{};
    kx_keypair<>* const placed =
        std::construct_at(reinterpret_cast<kx_keypair<>*>(storage.data()), std::move(taken));
    BOOST_TEST(!memory_is_zero(placed, secret_key_size));
    std::destroy_at(placed);
    BOOST_TEST(memory_is_zero(storage.data(), secret_key_size));
}

}  // namespace

int main() {
    key_pairs();
    return webcpp::test::exit_status(boost::report_errors());
}
