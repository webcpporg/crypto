// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 libsodium's key exchange, `crypto_kx`: a key pair on Curve25519 made from a 32-byte seed, and
 the two 32-byte session keys a client and a server compute from each other's public key, one
 to receive with and one to transmit with, the client's transmit key the server's receive key.

 The family's default backend, libsodium on every target, is included when the program links
 it; a program that uses the family without linking it stops where it calls it, with the
 Jamfile line that links it.

 The namespace is named by the problem the construction solves, agreeing session keys: crypto_kx
 is a construction over X25519 and BLAKE2b, not a curve primitive, so it is not in `curves`,
 and "hybrid encryption" (a KEM with a DEM) does not describe it either, a word left free for
 the post-quantum hybrids (X25519MLKEM768, X-Wing).

 @see "Key exchange: webcpp::crypto::key_exchange", in the guide.
*/
#ifndef WEBCPP_CRYPTO_KEY_EXCHANGE_KX_HPP
#define WEBCPP_CRYPTO_KEY_EXCHANGE_KX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: random_device draws generate()'s seed
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto::detail {

/**
 * What a `crypto_kx` key pair stores on a backend whose header does not specialise it: nothing,
 * since its engine refuses the backend where the family is called.
 */
template <class Name, class Backend>
struct kx_state {};

/** The work of `crypto_kx` on a backend; the primary refuses (defined at the end of this header).
 */
template <class Name, class Backend>
struct kx_engine;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::key_exchange {

/** The session keys of one side: what it receives with and what it transmits with. */
struct session_keys {
    /** The key this side decrypts what the peer sends with: the peer's `transmit`. */
    secret<32> receive;
    /** The key this side encrypts what it sends with: the peer's `receive`. */
    secret<32> transmit;
};

/**
 * A `crypto_kx` key pair: its secret key, kept by the backend and wiped by every move and by the
 * destructor, and its public key, which the peer receives.
 *
 * A client computes its session keys
 * with `client_session_keys` from the server's public key, the server with `server_session_keys`
 * from the client's: each side's `transmit` is the other's `receive`.
 *
 * The session keys are libsodium's construction, BLAKE2b-512 of the X25519 shared secret and
 * both public keys, client first: only another `crypto_kx` derives them.
 *
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::kx>`).
 */
template <class Backend = default_backend_t<families::kx>>
class kx_keypair {
    using state_type = detail::kx_state<families::kx, Backend>;
    using engine = detail::kx_engine<families::kx, Backend>;

public:
    /** The family, for `supports_v`. */
    using family_type = families::kx;
    /** The algorithm, for `supports_v`: the family's one name. */
    using name_type = families::kx;
    /** The backend. */
    using backend_type = Backend;
    /** The seed's size. */
    static constexpr std::size_t seed_size = 32;
    /** The public key's size. */
    static constexpr std::size_t public_key_size = 32;
    /** Each session key's size. */
    static constexpr std::size_t session_key_size = 32;

    /**
     * Derives a key pair from a seed, `crypto_kx_seed_keypair`: the same seed gives the same key
     * pair, its secret BLAKE2b-256 of the seed.
     *
     * @param seed_bytes 32 bytes.
     * @return The key pair; `invalid_key_size`; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<kx_keypair> derive_from_seed(
        std::span<std::uint8_t const> seed_bytes) noexcept {
        detail::timing_guard const timing_scope;
        if (seed_bytes.size() != seed_size) {
            return error::invalid_key_size;
        }
        kx_keypair made_pair;
        auto const engine_keyed =
            engine::seed_keypair(made_pair.state_, seed_bytes.template first<seed_size>());
        if (!engine_keyed) {
            return engine_keyed.error();
        }
        made_pair.keyed_ = true;
        return made_pair;
    }

    /**
     * Makes a key pair from a fresh seed, drawn from the system's generator.
     *
     * @return The key pair; `entropy_unavailable` when the system's generator fails or there is
     * none; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<kx_keypair> generate() noexcept {
        detail::timing_guard const timing_scope;
        secret<seed_size> seed_secret;
        auto const entropy_drawn =
            random_device().fill(seed_secret.writable());  // lint-world: the seed
        if (!entropy_drawn) {
            // The generator's not_supported (an Emscripten audio worklet) is the same failure
            // for a key pair: one error to handle.
            return error::entropy_unavailable;
        }
        return derive_from_seed(seed_secret.bytes());
    }

    /**
     * Moves the key pair; the source is wiped and empty.
     *
     * @param moved_from The key pair moved from.
     */
    kx_keypair(kx_keypair&& moved_from) noexcept : keyed_(std::exchange(moved_from.keyed_, false)) {
        state_ = moved_from.state_;
        engine::reset(moved_from.state_);
    }

    /**
     * Moves over this key pair, which is wiped first.
     *
     * @param moved_from The key pair moved from, wiped and empty after.
     * @return This key pair.
     */
    kx_keypair& operator=(kx_keypair&& moved_from) noexcept {
        if (this != &moved_from) {
            engine::reset(state_);
            keyed_ = std::exchange(moved_from.keyed_, false);
            state_ = moved_from.state_;
            engine::reset(moved_from.state_);
        }
        return *this;
    }

    /** Not copyable: a secret key has one owner. */
    kx_keypair(kx_keypair const&) = delete;
    /** Not copyable: a secret key has one owner. */
    kx_keypair& operator=(kx_keypair const&) = delete;

    /** Wipes the secret key. */
    ~kx_keypair() { engine::reset(state_); }

    /**
     * The public key, which the peer needs.
     *
     * @return 32 bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> public_key() const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        std::array<std::uint8_t, 32> key_bytes{};
        engine::public_key(state_, key_bytes);
        return key_bytes;
    }

    /**
     * The client's keys, from the server's public key, `crypto_kx_client_session_keys`.
     *
     * @param server_public_key 32 bytes.
     * @return The session keys; `invalid_state` moved from; `invalid_public_key` for a key of
     * another size; `weak_public_key` for a key of low order, whose X25519 shared secret is all
     * zero; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<session_keys> client_session_keys(
        std::span<std::uint8_t const> server_public_key) const noexcept {
        detail::timing_guard const timing_scope;
        return session<true>(server_public_key);
    }

    /**
     * The server's keys, from the client's public key, `crypto_kx_server_session_keys`.
     *
     * @param client_public_key 32 bytes.
     * @return The session keys; `invalid_state` moved from; `invalid_public_key` for a key of
     * another size; `weak_public_key` for a key of low order, whose X25519 shared secret is all
     * zero; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<session_keys> server_session_keys(
        std::span<std::uint8_t const> client_public_key) const noexcept {
        detail::timing_guard const timing_scope;
        return session<false>(client_public_key);
    }

private:
    kx_keypair() noexcept = default;

    /**
     * One side's computation, the client's or the server's: the guards both share, then a direct
     * call of the engine's function for that side.
     */
    template <bool Client>
    [[nodiscard]] boost::system::result<session_keys> session(
        std::span<std::uint8_t const> peer_public_key) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (peer_public_key.size() != public_key_size) {
            return error::invalid_public_key;
        }
        session_keys derived_keys;
        auto const peer_bytes = peer_public_key.first<public_key_size>();
        auto const engine_done =
            Client ? engine::client(state_, peer_bytes, derived_keys.receive.writable(),
                                    derived_keys.transmit.writable())
                   : engine::server(state_, peer_bytes, derived_keys.receive.writable(),
                                    derived_keys.transmit.writable());
        if (!engine_done) {
            return engine_done.error();
        }
        return derived_keys;
    }

    state_type state_{};
    bool keyed_ = false;
};

}  // namespace webcpp::crypto::key_exchange

namespace webcpp::crypto::detail {

/**
 * `crypto_kx`'s engine on a backend whose header does not specialise it: the family's refusal,
 * which names what the program needs (`detail/capabilities.hpp`). Its functions are never
 * called: the refusal stops the build where the class is instantiated, and they keep the
 * compiler from adding errors of their own after it; those that return report
 * `backend_failure`, so that a path the refusal missed fails closed.
 */
template <class Name, class Backend>
struct kx_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_KX(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> seed_keypair(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void public_key(Arguments&&... /*arguments*/) noexcept {}

    /** Never called; fails closed. */
    [[nodiscard]] static boost::system::result<void> client(
        kx_state<Name, Backend> const& /*keyed*/, std::span<std::uint8_t const, 32> /*peer*/,
        std::span<std::uint8_t, 32> /*receive*/,
        std::span<std::uint8_t, 32> /*transmit*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    [[nodiscard]] static boost::system::result<void> server(
        kx_state<Name, Backend> const& /*keyed*/, std::span<std::uint8_t const, 32> /*peer*/,
        std::span<std::uint8_t, 32> /*receive*/,
        std::span<std::uint8_t, 32> /*transmit*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_KX_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_KEY_EXCHANGE_KX_HPP
