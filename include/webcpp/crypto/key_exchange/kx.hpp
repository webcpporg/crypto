// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 libsodium's key exchange, `crypto_kx`, on X25519's typed keys: a key pair that holds an
 X25519 key pair, made from one, drawn, or derived from a 32-byte seed as libsodium does, and the
 two 32-byte session keys a client and a server compute from each other's X25519 public key,
 one to receive with and one to transmit with, the client's transmit key the server's receive
 key.

 The family's default backend, libsodium on every target, is included when the program links
 it; a program that uses the family without linking it stops where it calls it, with the
 Jamfile line that links it.

 The namespace is named by the problem the construction solves, agreeing session keys: crypto_kx
 is a construction over X25519 and BLAKE2b, not a curve primitive, so it is not in `curves`,
 and "hybrid encryption" (a KEM with a DEM) does not describe it either, a word left free for
 the post-quantum hybrids (X25519MLKEM768, X-Wing).

 @see "Key exchange: `webcpp::crypto::key_exchange`", in the guide.
*/
#ifndef WEBCPP_CRYPTO_KEY_EXCHANGE_KX_HPP
#define WEBCPP_CRYPTO_KEY_EXCHANGE_KX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/curves/x25519.hpp>
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

/** The work of `crypto_kx` on a backend; the primary refuses (defined at the end of this header).
 */
template <class Name, class Backend>
struct kx_engine;

/**
 * Whether a backend's header specialises `kx_engine` for it: set by that header beside its
 * specialisation. Where it is not, `kx_keypair::derive_from_seed` reaches the primary's refusal
 * alone and makes no X25519 key pair, whose own refusal would add a second error after it.
 */
template <class Backend>
inline constexpr bool kx_engine_defined = false;

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
 * A `crypto_kx` key pair: an X25519 key pair (`curves::x25519::basic_keypair`), whose secret key
 * it wipes by every move and by the destructor, and whose public key the peer receives.
 *
 * It is made from an X25519 key pair (`from_keypair`), which it takes as is, from a fresh one
 * (`generate`), or from a 32-byte seed as libsodium's `crypto_kx_seed_keypair` does
 * (`derive_from_seed`), whose secret key is BLAKE2b-256 of the seed: the same 32 bytes give two
 * key pairs, the seed hashed first.
 *
 * A client computes its session keys
 * with `client_session_keys` from the server's public key, the server with `server_session_keys`
 * from the client's: each side's `transmit` is the other's `receive`.
 *
 * The session keys are libsodium's construction, BLAKE2b-512 of the X25519 shared secret and
 * both public keys, client first: only another `crypto_kx` derives them.
 *
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::kx>`), and
 * that of the X25519 key pair it holds.
 */
template <class Backend = default_backend_t<families::kx>>
class kx_keypair {
    using engine = detail::kx_engine<families::kx, Backend>;
    using access = detail::x25519_access;

public:
    /** The family, for `supports_v`. */
    using family_type = families::kx;
    /** The algorithm, for `supports_v`: the family's one name. */
    using name_type = families::kx;
    /** The backend. */
    using backend_type = Backend;
    /** The X25519 key pair it holds. */
    using keypair_type = curves::x25519::basic_keypair<Backend>;
    /** The public key's type, which the peer's session keys take. */
    using public_key_type = curves::x25519::public_key;
    /** The seed's size. */
    static constexpr std::size_t seed_size = 32;
    /** The public key's size. */
    static constexpr std::size_t public_key_size = 32;
    /** Each session key's size. */
    static constexpr std::size_t session_key_size = 32;

    // A backend that has crypto_kx but no X25519 cannot make the key pair this one holds:
    // refused where the class is named. A backend without crypto_kx is refused by its engine
    // alone.
    static_assert(!detail::supported<families::kx, families::kx, Backend> ||
                      detail::supported<families::x25519, families::x25519, Backend>,
                  "webcpp::crypto: key_exchange::kx_keypair holds an X25519 key pair of its own "
                  "backend, which has no X25519.");

    /**
     * Takes an X25519 key pair as it is: its secret key is the key pair's, as `crypto_kx` uses
     * it, with no hash (`derive_from_seed` hashes its seed).
     *
     * @param key_pair The key pair, moved in: the result owns its secret key.
     * @return The key pair; `invalid_state` for a key pair moved from.
     */
    [[nodiscard]] static boost::system::result<kx_keypair> from_keypair(
        keypair_type key_pair) noexcept {
        detail::timing_guard const timing_scope;
        if (!access::keyed(key_pair)) {
            return error::invalid_state;
        }
        return kx_keypair(std::move(key_pair));
    }

    /**
     * Derives a key pair from a seed, `crypto_kx_seed_keypair`: the same seed gives the same key
     * pair, its secret key BLAKE2b-256 of the seed, not the seed itself.
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
        if constexpr (!detail::kx_engine_defined<Backend>) {
            // The engine's refusal stops the build here, and X25519's key pair is not made, so
            // that its own refusal adds no second error (never compiled into a program).
            return engine::seed_keypair(seed_bytes).error();
        } else {
            secret<keypair_type::secret_key_size> derived_secret;
            auto const engine_derived = engine::seed_keypair(seed_bytes.template first<seed_size>(),
                                                             derived_secret.writable());
            if (!engine_derived) {
                return engine_derived.error();
            }
            auto derived_pair = keypair_type::from_secret(derived_secret.bytes());
            if (!derived_pair) {
                return derived_pair.error();
            }
            return kx_keypair(std::move(derived_pair).unsafe_value());
        }
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
     * The X25519 key pair it holds, for a program that keeps its secret key (`secret()`) or
     * agrees with it through X25519 itself.
     *
     * @return The key pair, valid while this one lives; moved from, an empty one, every member
     * of which refuses with `invalid_state`.
     */
    [[nodiscard]] keypair_type const& keypair() const noexcept { return key_pair_; }

    /**
     * The public key, which the peer needs: the X25519 key pair's.
     *
     * @return The public key; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<public_key_type> public_key() const noexcept {
        return key_pair_.public_key();
    }

    /**
     * The client's keys, from the server's public key, `crypto_kx_client_session_keys`.
     *
     * @param server_public_key The server's X25519 public key.
     * @return The session keys; `invalid_state` moved from; `weak_public_key` for a key of low
     * order, whose X25519 shared secret is all zero; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<session_keys> client_session_keys(
        public_key_type const& server_public_key) const noexcept {
        detail::timing_guard const timing_scope;
        return session<true>(server_public_key);
    }

    /**
     * The server's keys, from the client's public key, `crypto_kx_server_session_keys`.
     *
     * @param client_public_key The client's X25519 public key.
     * @return The session keys; `invalid_state` moved from; `weak_public_key` for a key of low
     * order, whose X25519 shared secret is all zero; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<session_keys> server_session_keys(
        public_key_type const& client_public_key) const noexcept {
        detail::timing_guard const timing_scope;
        return session<false>(client_public_key);
    }

    /**
     * Moves the key pair; the source is wiped and empty.
     *
     * @param moved_from The key pair moved from.
     */
    kx_keypair(kx_keypair&& moved_from) noexcept = default;

    /**
     * Moves over this key pair, whose secret key is wiped first.
     *
     * @param moved_from The key pair moved from, wiped and empty after.
     * @return This key pair.
     */
    kx_keypair& operator=(kx_keypair&& moved_from) noexcept = default;

    /** Not copyable: a secret key has one owner. */
    kx_keypair(kx_keypair const&) = delete;
    /** Not copyable: a secret key has one owner. */
    kx_keypair& operator=(kx_keypair const&) = delete;

    /** Wipes the secret key. */
    ~kx_keypair() = default;

private:
    explicit kx_keypair(keypair_type&& key_pair) noexcept : key_pair_(std::move(key_pair)) {}

    /**
     * One side's computation, the client's or the server's: the guard both share, then a direct
     * call of the engine's function for that side, with the key pair's bytes.
     */
    template <bool Client>
    [[nodiscard]] boost::system::result<session_keys> session(
        public_key_type const& peer_public_key) const noexcept {
        if (!access::keyed(key_pair_)) {
            return error::invalid_state;
        }
        session_keys derived_keys;
        auto const secret_bytes = access::secret_bytes(key_pair_);
        auto const public_bytes = access::public_bytes(key_pair_);
        std::span<std::uint8_t const, public_key_size> const peer_bytes = peer_public_key.bytes();
        auto const engine_done =
            Client
                ? engine::client(secret_bytes, public_bytes, peer_bytes,
                                 derived_keys.receive.writable(), derived_keys.transmit.writable())
                : engine::server(secret_bytes, public_bytes, peer_bytes,
                                 derived_keys.receive.writable(), derived_keys.transmit.writable());
        if (!engine_done) {
            return engine_done.error();
        }
        return derived_keys;
    }

    keypair_type key_pair_;
};

}  // namespace webcpp::crypto::key_exchange

namespace webcpp::crypto::detail {

/**
 * `crypto_kx`'s engine on a backend whose header does not specialise it: the family's refusal,
 * which names what the program needs (`detail/capabilities.hpp`). Its functions are never
 * called: the refusal stops the build where the class is instantiated, and they keep the
 * compiler from adding errors of their own after it; they report `backend_failure`, so that a
 * path the refusal missed fails closed.
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

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> client(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> server(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace webcpp::crypto::detail

/** Defined once this header's declarations are, which libsodium's engine specialises. */
// NOLINTNEXTLINE(modernize-macro-to-enum): read by backends/sodium.hpp's #if, not a value
#define WEBCPP_CRYPTO_DETAIL_KX_DECLARED 1

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_KX_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_KEY_EXCHANGE_KX_HPP
