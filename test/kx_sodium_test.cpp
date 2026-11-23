// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto_kx on libsodium, on X25519's typed keys: libsodium's test/default/kx.exp, the client's key
// pair made from the seed 00..1f and the server's from that seed incremented, their public keys and
// session keys libsodium's; a client and a server of other seeds, the client's transmit key the
// server's receive key and the reverse; a seed is not a secret: derive_from_seed gives the keys of
// libsodium's crypto_kx_seed_keypair, called here, and differs from from_keypair of an X25519 key
// pair made from the same bytes; from_keypair keeps the key pair it takes; a peer key of small
// order (kx.c's) and the all-zero key refused with weak_public_key on both sides; a changed peer
// key changing the keys; the guards (seeds of other sizes, a moved-from key pair, a moved-from
// X25519 key pair given to from_keypair); generate() under the planted entropy source of the test
// seam WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY, failing and answering; and the session keys are
// secret<32>, which wipe themselves.

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/key_exchange/kx.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <sodium/crypto_kx.h>

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
namespace key_exchange = webcpp::crypto::key_exchange;
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

using kx_keypair = key_exchange::kx_keypair<>;

/** The bytes of a session key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(crypto::secret<32> const& key) {
    auto const view = key.bytes();
    return {view.begin(), view.end()};
}

/** The bytes of a public key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(x25519::public_key const& key) {
    return {key.bytes().begin(), key.bytes().end()};
}

/** The bytes of an array, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(std::array<std::uint8_t, 32> const& bytes) {
    return {bytes.begin(), bytes.end()};
}

/** A public key made from bytes a test holds. */
x25519::public_key public_key_of(std::span<std::uint8_t const> bytes) {
    return x25519::public_key::from_bytes(bytes).value();
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
    auto const client = kx_keypair::derive_from_seed(client_seed());
    auto const server =
        key_exchange::kx_keypair<crypto::backends::sodium>::derive_from_seed(server_seed());
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
    // kx.exp's client_pk; its client_sk, which the key pair keeps, kx_wipe_sodium_test reads.
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
    auto const client = kx_keypair::derive_from_seed(client_seed());
    auto const server = kx_keypair::derive_from_seed(server_seed());
    BOOST_TEST(client.has_value() && server.has_value());
    if (!client || !server) {
        return;
    }
    auto const client_public = client->public_key();
    BOOST_TEST(client_public.has_value());
    if (!client_public) {
        return;
    }
    auto changed = client_public->bytes();
    ++changed[0];
    auto const keys = server->server_session_keys(public_key_of(changed));
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
    auto const key = kx_keypair::derive_from_seed(client_seed());
    BOOST_TEST(key.has_value());
    if (!key) {
        return;
    }
    std::array<std::uint8_t, 32> const zero{};
    for (auto const& peer : {public_key_of(small_order), public_key_of(zero)}) {
        auto const as_client = key->client_session_keys(peer);
        auto const as_server = key->server_session_keys(peer);
        BOOST_TEST(as_client.has_error() && as_client.error() == crypto::error::weak_public_key);
        BOOST_TEST(as_server.has_error() && as_server.error() == crypto::error::weak_public_key);
    }
}

void guards() {
    std::array<std::uint8_t, 33> const long_bytes{};
    BOOST_TEST(kx_keypair::derive_from_seed(std::span(long_bytes).first(31)).error() ==
               crypto::error::invalid_key_size);
    BOOST_TEST(kx_keypair::derive_from_seed(long_bytes).error() == crypto::error::invalid_key_size);
    BOOST_TEST(kx_keypair::derive_from_seed(std::span<std::uint8_t const>{}).error() ==
               crypto::error::invalid_key_size);

    // An X25519 key pair moved from holds no key: from_keypair refuses it.
    auto inner = x25519::keypair::from_secret(client_seed());
    BOOST_TEST(inner.has_value());
    if (!inner) {
        return;
    }
    x25519::keypair const kept = std::move(*inner);
    BOOST_TEST(kept.public_key().has_value());
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from pair
    auto const refused = kx_keypair::from_keypair(std::move(*inner));
    BOOST_TEST(refused.has_error() && refused.error() == crypto::error::invalid_state);
}

/**
 * A client and a server (the spec's scenario), each from a seed of its own (generate() draws
 * from the planted source here, the same bytes every time): what the client transmits with, the
 * server receives with, and the reverse; the two directions differ.
 */
void client_server() {
    std::array<std::uint8_t, 32> client_bytes{};
    std::array<std::uint8_t, 32> server_bytes{};
    client_bytes.fill(0x11);
    server_bytes.fill(0x22);
    auto const client = kx_keypair::derive_from_seed(client_bytes);
    auto const server = kx_keypair::derive_from_seed(server_bytes);
    BOOST_TEST(client.has_value() && server.has_value());
    if (!client || !server) {
        return;
    }
    auto const client_public = client->public_key();
    auto const server_public = server->public_key();
    BOOST_TEST(client_public.has_value() && server_public.has_value());
    if (!client_public || !server_public) {
        return;
    }
    BOOST_TEST(*client_public != *server_public);
    auto const client_keys = client->client_session_keys(*server_public);
    auto const server_keys = server->server_session_keys(*client_public);
    BOOST_TEST(client_keys.has_value() && server_keys.has_value());
    if (!client_keys || !server_keys) {
        return;
    }
    BOOST_TEST(bytes_of(client_keys->transmit) == bytes_of(server_keys->receive));
    BOOST_TEST(bytes_of(client_keys->receive) == bytes_of(server_keys->transmit));
    BOOST_TEST(bytes_of(client_keys->transmit) != bytes_of(client_keys->receive));
}

/** A seed, 32 bytes of 0x5a, from which the checks below derive a key pair. */
std::array<std::uint8_t, 32> plain_seed() {
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x5a);
    return seed;
}

/** libsodium's crypto_kx_seed_keypair of a seed, called here: its public and secret keys. */
struct sodium_pair {
    std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES> public_key{};
    std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES> secret_key{};
};

/** Calls libsodium's crypto_kx_seed_keypair on a seed. */
sodium_pair sodium_seed_keypair(std::array<std::uint8_t, 32> const& seed) {
    sodium_pair made;
    BOOST_TEST(
        crypto_kx_seed_keypair(made.public_key.data(), made.secret_key.data(), seed.data()) == 0);
    return made;
}

/** Session keys that hold `receive` and `transmit`. */
void expect_keys(boost::system::result<key_exchange::session_keys> const& keys,
                 std::array<std::uint8_t, 32> const& receive,
                 std::array<std::uint8_t, 32> const& transmit) {
    BOOST_TEST(keys.has_value());
    if (keys) {
        BOOST_TEST(bytes_of(keys->receive) == bytes_of(receive));
        BOOST_TEST(bytes_of(keys->transmit) == bytes_of(transmit));
    }
}

/**
 * A seed is not a secret (the spec's scenario): derive_from_seed gives the public key of
 * libsodium's crypto_kx_seed_keypair, called here, and its secret key, BLAKE2b-256 of the seed;
 * from_keypair of an X25519 key pair made from the same 32 bytes takes them as the secret itself,
 * and its public key differs.
 */
void seed_is_not_secret() {
    auto const seed = plain_seed();
    auto const derived = kx_keypair::derive_from_seed(seed);
    BOOST_TEST(derived.has_value());
    if (!derived) {
        return;
    }
    auto const sodium = sodium_seed_keypair(seed);
    auto const derived_public = derived->public_key();
    BOOST_TEST(derived_public.has_value() &&
               bytes_of(*derived_public) == bytes_of(sodium.public_key));
    // Its secret is libsodium's, BLAKE2b-256 of the seed, not the seed.
    auto const derived_secret = derived->keypair().secret();
    BOOST_TEST(derived_secret.has_value() &&
               bytes_of(*derived_secret) == bytes_of(sodium.secret_key));
    BOOST_TEST(bytes_of(sodium.secret_key) != bytes_of(seed));

    // The same 32 bytes as an X25519 secret give another key pair.
    auto const inner = x25519::keypair::from_secret(seed);
    BOOST_TEST(inner.has_value());
    if (!inner || !derived_public) {
        return;
    }
    auto const inner_public = inner->public_key();
    auto const wrapped = kx_keypair::from_keypair(*x25519::keypair::from_secret(seed));
    BOOST_TEST(wrapped.has_value());
    if (wrapped) {
        auto const wrapped_public = wrapped->public_key();
        BOOST_TEST(wrapped_public.has_value() && *wrapped_public != *derived_public);
        BOOST_TEST(wrapped_public.has_value() && *wrapped_public == *inner_public);
    }
}

/**
 * The session keys of a seed's key pair, both sides, are libsodium's from crypto_kx_seed_keypair's
 * keys, crypto_kx_client_session_keys and crypto_kx_server_session_keys called here.
 */
void seed_sessions() {
    auto const seed = plain_seed();
    auto const derived = kx_keypair::derive_from_seed(seed);
    auto const peer = kx_keypair::derive_from_seed(server_seed());
    BOOST_TEST(derived.has_value() && peer.has_value());
    if (!derived || !peer) {
        return;
    }
    auto const peer_public = peer->public_key();
    BOOST_TEST(peer_public.has_value());
    if (!peer_public) {
        return;
    }
    auto const sodium = sodium_seed_keypair(seed);
    std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> receive{};
    std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> transmit{};
    BOOST_TEST(crypto_kx_client_session_keys(receive.data(), transmit.data(),
                                             sodium.public_key.data(), sodium.secret_key.data(),
                                             peer_public->bytes().data()) == 0);
    expect_keys(derived->client_session_keys(*peer_public), receive, transmit);
    BOOST_TEST(crypto_kx_server_session_keys(receive.data(), transmit.data(),
                                             sodium.public_key.data(), sodium.secret_key.data(),
                                             peer_public->bytes().data()) == 0);
    expect_keys(derived->server_session_keys(*peer_public), receive, transmit);
}

/** A client's and a server's keys mirror each other: one's transmit is the other's receive. */
void expect_mirrored(kx_keypair const& client, kx_keypair const& server) {
    auto const client_public = client.public_key();
    auto const server_public = server.public_key();
    BOOST_TEST(client_public.has_value() && server_public.has_value());
    if (!client_public || !server_public) {
        return;
    }
    auto const client_keys = client.client_session_keys(*server_public);
    auto const server_keys = server.server_session_keys(*client_public);
    BOOST_TEST(client_keys.has_value() && server_keys.has_value());
    if (client_keys && server_keys) {
        BOOST_TEST(bytes_of(client_keys->transmit) == bytes_of(server_keys->receive));
        BOOST_TEST(bytes_of(client_keys->receive) == bytes_of(server_keys->transmit));
    }
}

/**
 * from_keypair keeps the key pair it takes: keypair() gives it back, its public key and its
 * secret key; public_key() is the key pair's; the key pair given is moved from; and it agrees
 * with a peer as crypto_kx does.
 */
void from_keypair_keeps() {
    auto inner = x25519::keypair::from_secret(client_seed());
    BOOST_TEST(inner.has_value());
    if (!inner) {
        return;
    }
    auto const inner_public = inner->public_key();
    auto const inner_secret = inner->secret();
    auto const wrapped = kx_keypair::from_keypair(std::move(*inner));
    BOOST_TEST(wrapped.has_value() && inner_public.has_value() && inner_secret.has_value());
    if (!wrapped || !inner_public || !inner_secret) {
        return;
    }
    auto const kept_public = wrapped->keypair().public_key();
    BOOST_TEST(kept_public.has_value() && *kept_public == *inner_public);
    auto const kept_secret = wrapped->keypair().secret();
    BOOST_TEST(kept_secret.has_value() && bytes_of(*kept_secret) == bytes_of(*inner_secret));
    auto const wrapped_public = wrapped->public_key();
    BOOST_TEST(wrapped_public.has_value() && *wrapped_public == *inner_public);
    // The key pair given was moved from: the kx key pair owns the secret now.
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from pair
    BOOST_TEST(inner->public_key().error() == crypto::error::invalid_state);

    auto const server = kx_keypair::derive_from_seed(server_seed());
    BOOST_TEST(server.has_value());
    if (server) {
        expect_mirrored(*wrapped, *server);
    }
}

void moves() {
    auto made = kx_keypair::derive_from_seed(client_seed());
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
    auto other = kx_keypair::derive_from_seed(server_seed());
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
    auto const made = kx_keypair::derive_from_seed(seed);
    BOOST_TEST(drawn.has_value() && made.has_value());
    if (drawn && made) {
        auto const drawn_key = drawn->public_key();
        auto const made_key = made->public_key();
        BOOST_TEST(drawn_key && made_key && *drawn_key == *made_key);
    }
}

/** Whether a key pair's session keys can be asked with a peer of type Peer. */
template <class Peer>
concept takes_peer = requires(kx_keypair const& key_pair, Peer const& peer) {
    key_pair.client_session_keys(peer);
    key_pair.server_session_keys(peer);
};

// A peer is an X25519 public key: its bytes are not taken (design D3).
static_assert(takes_peer<x25519::public_key>);
static_assert(!takes_peer<std::array<std::uint8_t, 32>>);
static_assert(!takes_peer<std::span<std::uint8_t const>>);
// public_key() is X25519's public key, and keypair() the X25519 key pair it holds.
static_assert(std::is_same_v<decltype(std::declval<kx_keypair const&>().public_key()),
                             boost::system::result<x25519::public_key>>);
static_assert(std::is_same_v<decltype(std::declval<kx_keypair const&>().keypair()),
                             x25519::basic_keypair<crypto::backends::sodium> const&>);

// The session keys are secret<32>, which wipe themselves; the key pair has one owner.
static_assert(std::is_same_v<decltype(key_exchange::session_keys::receive), crypto::secret<32>>);
static_assert(std::is_same_v<decltype(key_exchange::session_keys::transmit), crypto::secret<32>>);
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
    client_server();
    seed_is_not_secret();
    seed_sessions();
    from_keypair_keeps();
    moves();
    generated();
    return test::exit_status(boost::report_errors());
}
