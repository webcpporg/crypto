// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto_kx on libsodium: libsodium's test/default/kx.exp, the client's key pair made from the
// seed 00..1f and the server's from that seed incremented, their public keys and session keys
// libsodium's; the client's transmit key the server's receive key and the reverse; a peer key
// of small order (kx.c's) and the all-zero key refused with weak_public_key on both sides; a
// changed peer key changing the keys; the guards (seeds and peer keys of other sizes, a
// moved-from key pair); generate() under the planted entropy source of the test seam
// WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY, failing and answering; and the session keys are
// secret<32>, which wipe themselves.

#include <webcpp/crypto/curves/x25519/kx.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace test = webcpp::test;

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
bool entropy_fails = false;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
int entropy_errno = EIO;

}  // namespace

// The planted source: 0x42 in every byte, or -1 with errno set, as getentropy fails.
extern "C" int webcpp_test_entropy(void* output_bytes, std::size_t byte_count) {
    if (entropy_fails) {
        errno = entropy_errno;
        return -1;
    }
    std::memset(output_bytes, 0x42, byte_count);
    return 0;
}

namespace {

using kx_keypair = x25519::kx_keypair<>;

/** The bytes of a session key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(crypto::secret<32> const& key) {
    auto const view = key.bytes();
    return {view.begin(), view.end()};
}

/** The bytes of a public key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(std::array<std::uint8_t, 32> const& key) {
    return {key.begin(), key.end()};
}

/** kx.c's seed: the bytes 0 to 31. */
std::array<std::uint8_t, 32> client_seed() {
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i);
    }
    return seed;
}

/** kx.c's seed after sodium_increment, a little-endian increment: its first byte is 1. */
std::array<std::uint8_t, 32> server_seed() {
    auto seed = client_seed();
    seed[0] = 1;
    return seed;
}

/** kx.c's peer key of small order. */
constexpr std::array<std::uint8_t, 32> small_order{
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
};

void kx_exp() {
    auto const client = kx_keypair::make(client_seed());
    auto const server = x25519::kx_keypair<crypto::backends::sodium>::make(server_seed());
    BOOST_TEST(client.has_value());
    BOOST_TEST(server.has_value());
    if (!client || !server) {
        return;
    }
    auto const client_public = client->public_key();
    auto const server_public = server->public_key();
    BOOST_TEST(client_public.has_value());
    BOOST_TEST(server_public.has_value());
    if (!client_public || !server_public) {
        return;
    }
    // kx.exp's client_pk; its client_sk is the seed's BLAKE2b, which the key pair keeps.
    BOOST_TEST(bytes_of(*client_public) ==
               test::from_hex("0e0216223f147143d32615a91189c288c1728cba3cc5f9f621b1026e03d83129"));

    auto const server_keys = server->server_session_keys(*client_public);
    auto const client_keys = client->client_session_keys(*server_public);
    BOOST_TEST(server_keys.has_value());
    BOOST_TEST(client_keys.has_value());
    if (!server_keys || !client_keys) {
        return;
    }
    auto const one_way =
        test::from_hex("62c8f4fa81800abd0577d99918d129b65deb789af8c8351f391feb0cbf238604");
    auto const other_way =
        test::from_hex("749519c68059bce69f7cfcc7b387a3de1a1e8237d110991323bf62870115731a");
    // kx.exp's server_rx, server_tx, client_rx and client_tx.
    BOOST_TEST(bytes_of(server_keys->receive) == one_way);
    BOOST_TEST(bytes_of(server_keys->transmit) == other_way);
    BOOST_TEST(bytes_of(client_keys->receive) == other_way);
    BOOST_TEST(bytes_of(client_keys->transmit) == one_way);
    // What one side transmits with, the other receives with.
    BOOST_TEST(bytes_of(client_keys->transmit) == bytes_of(server_keys->receive));
    BOOST_TEST(bytes_of(client_keys->receive) == bytes_of(server_keys->transmit));
    // The two directions differ.
    BOOST_TEST(bytes_of(client_keys->transmit) != bytes_of(client_keys->receive));
}

void peer_key_counts() {
    // kx.c: the client's public key incremented changes the server's keys.
    auto const client = kx_keypair::make(client_seed());
    auto const server = kx_keypair::make(server_seed());
    BOOST_TEST(client.has_value() && server.has_value());
    if (!client || !server) {
        return;
    }
    auto changed = client->public_key();
    BOOST_TEST(changed.has_value());
    if (!changed) {
        return;
    }
    ++(*changed)[0];
    auto const keys = server->server_session_keys(*changed);
    BOOST_TEST(keys.has_value());
    if (keys) {
        BOOST_TEST(
            bytes_of(keys->receive) !=
            test::from_hex("62c8f4fa81800abd0577d99918d129b65deb789af8c8351f391feb0cbf238604"));
        BOOST_TEST(
            bytes_of(keys->transmit) !=
            test::from_hex("749519c68059bce69f7cfcc7b387a3de1a1e8237d110991323bf62870115731a"));
    }
}

void weak_peers() {
    auto const key = kx_keypair::make(client_seed());
    BOOST_TEST(key.has_value());
    if (!key) {
        return;
    }
    std::array<std::uint8_t, 32> const zero{};
    for (auto const& peer : {small_order, zero}) {
        auto const as_client = key->client_session_keys(peer);
        auto const as_server = key->server_session_keys(peer);
        BOOST_TEST(as_client.has_error() && as_client.error() == crypto::error::weak_public_key);
        BOOST_TEST(as_server.has_error() && as_server.error() == crypto::error::weak_public_key);
    }
}

void guards() {
    std::array<std::uint8_t, 33> const long_bytes{};
    BOOST_TEST(kx_keypair::make(std::span(long_bytes).first(31)).error() ==
               crypto::error::invalid_key_size);
    BOOST_TEST(kx_keypair::make(long_bytes).error() == crypto::error::invalid_key_size);
    BOOST_TEST(kx_keypair::make(std::span<std::uint8_t const>{}).error() ==
               crypto::error::invalid_key_size);

    auto made = kx_keypair::make(client_seed());
    BOOST_TEST(made.has_value());
    if (!made) {
        return;
    }
    auto const peer = made->public_key();
    BOOST_TEST(peer.has_value());
    if (!peer) {
        return;
    }
    BOOST_TEST(made->client_session_keys(std::span(long_bytes).first(31)).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(made->client_session_keys(long_bytes).error() == crypto::error::invalid_public_key);
    BOOST_TEST(made->server_session_keys(std::span(long_bytes).first(31)).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(made->server_session_keys(long_bytes).error() == crypto::error::invalid_public_key);
}

void moves() {
    auto made = kx_keypair::make(client_seed());
    BOOST_TEST(made.has_value());
    if (!made) {
        return;
    }
    auto const peer = made->public_key();
    BOOST_TEST(peer.has_value());
    if (!peer) {
        return;
    }

    // Moved from, the key pair is empty: every call is invalid_state.
    kx_keypair const taken = std::move(*made);
    BOOST_TEST(taken.public_key().has_value());
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from state
    BOOST_TEST(made->public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(made->client_session_keys(*peer).error() == crypto::error::invalid_state);
    BOOST_TEST(made->server_session_keys(*peer).error() == crypto::error::invalid_state);
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)

    // Moved over, the target holds the source's key pair.
    auto other = kx_keypair::make(server_seed());
    BOOST_TEST(other.has_value());
    if (other) {
        auto const other_public = other->public_key();
        *made = std::move(*other);
        auto const now = made->public_key();
        BOOST_TEST(other_public.has_value() && now.has_value());
        if (other_public && now) {
            BOOST_TEST(bytes_of(*now) == bytes_of(*other_public));
        }
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): moved from
        BOOST_TEST(other->public_key().error() == crypto::error::invalid_state);
    }
}

void generated() {
    // The source fails: no key pair, entropy_unavailable.
    entropy_fails = true;
    auto const refused = kx_keypair::generate();
    BOOST_TEST(refused.has_error() && refused.error() == crypto::error::entropy_unavailable);
    // No generator at all (ENOTSUP, an Emscripten audio worklet, which random_device reports as
    // not_supported) is the same failure for a key pair.
    entropy_errno = ENOTSUP;
    auto const unsupported = kx_keypair::generate();
    BOOST_TEST(unsupported.has_error() &&
               unsupported.error() == crypto::error::entropy_unavailable);
    entropy_errno = EIO;

    // The source answers: the key pair of the seed it gave, 32 bytes of 0x42.
    entropy_fails = false;
    auto const drawn = kx_keypair::generate();
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x42);
    auto const made = kx_keypair::make(seed);
    BOOST_TEST(drawn.has_value() && made.has_value());
    if (drawn && made) {
        auto const drawn_key = drawn->public_key();
        auto const made_key = made->public_key();
        BOOST_TEST(drawn_key && made_key && *drawn_key == *made_key);
    }
}

// The session keys are secret<32>, which wipe themselves; the key pair has one owner.
static_assert(std::is_same_v<decltype(x25519::session_keys::receive), crypto::secret<32>>);
static_assert(std::is_same_v<decltype(x25519::session_keys::transmit), crypto::secret<32>>);
static_assert(!std::is_copy_constructible_v<kx_keypair> && !std::is_copy_assignable_v<kx_keypair>);
static_assert(std::is_nothrow_move_constructible_v<kx_keypair> &&
              std::is_nothrow_move_assignable_v<kx_keypair>);
static_assert(!std::is_default_constructible_v<kx_keypair>);
// The key pair names its family, its name and its backend, as the capability table does.
static_assert(std::is_same_v<kx_keypair::family_type, crypto::families::kx>);
static_assert(std::is_same_v<kx_keypair::name_type, crypto::families::kx>);
static_assert(std::is_same_v<kx_keypair::backend_type, crypto::backends::sodium>);
static_assert(kx_keypair::seed_size == 32 && kx_keypair::public_key_size == 32 &&
              kx_keypair::session_key_size == 32);
static_assert(crypto::supports_v<kx_keypair, crypto::backends::sodium>);

}  // namespace

int main() {
    kx_exp();
    peer_key_counts();
    weak_peers();
    guards();
    moves();
    generated();
    return test::exit_status(boost::report_errors());
}
