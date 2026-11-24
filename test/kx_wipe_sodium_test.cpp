// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A crypto_kx key pair's secret key, held by the X25519 key pair inside it, is zero in its
// storage once moved from, once moved over and once destroyed, and a side's session keys are zero
// in theirs once destroyed, read at -O2 with every call inlined (the Jamfile's requirements),
// where a wipe the optimiser may drop as a dead store would be dropped. Where the secret key lies
// in the key pair is read once, alive, through detail::x25519_access, as an offset from the key
// pair's start, then probed at that offset after each move and after the destructor. Alive, the
// key pair made from kx.c's seed holds kx.exp's client_sk there.

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/key_exchange/kx.hpp>
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
namespace key_exchange = webcpp::crypto::key_exchange;

using key_exchange::kx_keypair;

// The secret key's size.
constexpr std::size_t secret_key_size = 32;
// A side's session keys are their two keys' bytes, nothing else.
static_assert(std::is_standard_layout_v<key_exchange::session_keys> &&
              sizeof(key_exchange::session_keys) == 64);

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

// Where the inner X25519 key pair keeps its secret key, from the start of a kx key pair's storage.
std::size_t secret_offset(kx_keypair<> const& key_pair) {
    auto const secret_bytes = crypto::detail::x25519_access::secret_bytes(key_pair.keypair());
    auto const* const start = reinterpret_cast<std::byte const*>(&key_pair);
    auto const* const secret = reinterpret_cast<std::byte const*>(secret_bytes.data());
    return static_cast<std::size_t>(secret - start);
}

// The secret key's storage, `offset` bytes into an object's storage.
void const* at(void const* where, std::size_t offset) {
    return static_cast<std::byte const*>(where) + offset;
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
    std::size_t const offset = secret_offset(*made);
    BOOST_TEST(offset + secret_key_size <= sizeof(kx_keypair<>));
    // Alive, the storage holds the secret key, kx.exp's client_sk: the checks below can fail.
    BOOST_TEST(
        bytes_at(at(&*made, offset), secret_key_size) ==
        webcpp::test::from_hex("cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6"));
    BOOST_TEST(!memory_is_zero(at(&*made, offset), secret_key_size));

    kx_keypair<> taken = std::move(*made);
    BOOST_TEST(memory_is_zero(at(&*made, offset), secret_key_size));

    auto other = kx_keypair<>::derive_from_seed(kx_c_seed);
    BOOST_TEST(other.has_value());
    if (other) {
        taken = std::move(*other);
        BOOST_TEST(memory_is_zero(at(&*other, offset), secret_key_size));
    }

    // Destroyed in storage this frame owns: its bytes are read after the destructor.
    alignas(kx_keypair<>) std::array<std::byte, sizeof(kx_keypair<>)> storage{};
    kx_keypair<>* const placed =
        std::construct_at(reinterpret_cast<kx_keypair<>*>(storage.data()), std::move(taken));
    BOOST_TEST(secret_offset(*placed) == offset);
    BOOST_TEST(!memory_is_zero(at(placed, offset), secret_key_size));
    std::destroy_at(placed);
    BOOST_TEST(memory_is_zero(at(storage.data(), offset), secret_key_size));
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
    alignas(key_exchange::session_keys) std::array<std::byte, sizeof(key_exchange::session_keys)>
        storage{};
    key_exchange::session_keys* const placed = std::construct_at(
        reinterpret_cast<key_exchange::session_keys*>(storage.data()), std::move(*keys));
    BOOST_TEST(!memory_is_zero(&placed->receive, 32));
    BOOST_TEST(!memory_is_zero(&placed->transmit, 32));
    std::destroy_at(placed);
    BOOST_TEST(memory_is_zero(storage.data(), sizeof(key_exchange::session_keys)));
}

}  // namespace

int main() {
    key_pairs();
    sessions();
    return webcpp::test::exit_status(boost::report_errors());
}
