// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A crypto_kx key pair's secret key is zero in its storage once moved from, once moved over and
// once destroyed, and a side's session keys are zero in theirs once destroyed, read at -O2 with
// every call inlined (the Jamfile's requirements), where a wipe the optimiser may drop as a dead
// store would be dropped. The secret key is the first member of the key pair's state, itself the
// key pair's first member, at the start of its storage: the classes are standard-layout, which
// the test asserts. Alive, the key pair made from kx.c's seed holds kx.exp's client_sk there,
// which the key pair's interface never shows.

#include <webcpp/crypto/curves/x25519/kx.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace crypto = webcpp::crypto;
namespace x25519 = webcpp::crypto::curves::x25519;

using x25519::kx_keypair;
using state = crypto::detail::kx_state<crypto::families::kx, crypto::backends::sodium>;

// The secret key's bytes, at the start of the state.
constexpr std::size_t secret_key_size = sizeof(state::secret_key);

static_assert(std::is_standard_layout_v<kx_keypair<>> && std::is_standard_layout_v<state>);
static_assert(secret_key_size == 32 && offsetof(state, secret_key) == 0);
// A side's session keys are their two keys' bytes, nothing else.
static_assert(std::is_standard_layout_v<x25519::session_keys> &&
              sizeof(x25519::session_keys) == 64);

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

// The count bytes at `where`, an object's storage read as bytes.
std::vector<std::uint8_t> bytes_at(void const* where, std::size_t count) {
    std::span<std::uint8_t const> const bytes(static_cast<std::uint8_t const*>(where), count);
    return {bytes.begin(), bytes.end()};
}

// libsodium's kx.c seed, the bytes 0 to 31.
constexpr std::array<std::uint8_t, 32> kx_c_seed{
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

void key_pairs() {
    auto made = kx_keypair<>::derive_from_seed(kx_c_seed);
    BOOST_TEST(made.has_value());
    if (!made) {
        return;
    }
    // Alive, the state holds the secret key, kx.exp's client_sk: the checks below can fail.
    BOOST_TEST(
        bytes_at(&*made, secret_key_size) ==
        webcpp::test::from_hex("cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6"));
    BOOST_TEST(!memory_is_zero(&*made, secret_key_size));

    kx_keypair<> taken = std::move(*made);
    BOOST_TEST(memory_is_zero(&*made, secret_key_size));

    auto other = kx_keypair<>::derive_from_seed(kx_c_seed);
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

void sessions() {
    auto server_seed = kx_c_seed;
    server_seed[0] = 1;  // kx.c's seed after sodium_increment
    auto const client = kx_keypair<>::derive_from_seed(kx_c_seed);
    auto const server = kx_keypair<>::derive_from_seed(server_seed);
    BOOST_TEST(client.has_value() && server.has_value());
    if (!client || !server) {
        return;
    }
    auto const server_public = server->public_key();
    BOOST_TEST(server_public.has_value());
    if (!server_public) {
        return;
    }
    auto keys = client->client_session_keys(*server_public);
    BOOST_TEST(keys.has_value());
    if (!keys) {
        return;
    }

    // Destroyed in storage this frame owns: its bytes are read after the destructor.
    alignas(x25519::session_keys) std::array<std::byte, sizeof(x25519::session_keys)> storage{};
    x25519::session_keys* const placed = std::construct_at(
        reinterpret_cast<x25519::session_keys*>(storage.data()), std::move(*keys));
    BOOST_TEST(!memory_is_zero(&placed->receive, 32));
    BOOST_TEST(!memory_is_zero(&placed->transmit, 32));
    std::destroy_at(placed);
    BOOST_TEST(memory_is_zero(storage.data(), sizeof(x25519::session_keys)));
}

}  // namespace

int main() {
    key_pairs();
    sessions();
    return webcpp::test::exit_status(boost::report_errors());
}
