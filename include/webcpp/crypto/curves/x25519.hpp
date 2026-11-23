// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 X25519 key agreement (RFC 7748) on typed keys: `curves::x25519::public_key`, made from its 32
 bytes, and `curves::x25519::basic_keypair`, made from a 32-byte secret key or drawn from the
 system's generator, which agrees a 32-byte shared secret with a peer's public key, refused when
 it is all zero.

 The family's default backend, libsodium on every target, is included when the program links
 it; a program that uses the family without linking it stops where it calls it, with the
 Jamfile line that links it.

 @see "X25519", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_X25519_HPP
#define WEBCPP_CRYPTO_CURVES_X25519_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/bytes.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: random_device draws generate()'s secret
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto::detail {

/** The work of X25519 on a backend; the primary refuses (defined at the end of this header). */
template <class Name, class Backend>
struct x25519_engine;

/**
 * X25519's work on a backend, without a guard (design R16): the public key of a secret key and
 * the shared secret of a secret key and a peer's public key, which the key pair and the
 * asynchronous family call once their own guard is held.
 *
 * @tparam Backend The backend.
 */
template <class Backend>
struct x25519_operations {
    /**
     * The public key of a secret key: its product with the base point, `u = 9`.
     *
     * @param secret_key 32 bytes; any 32 bytes are a secret key (RFC 7748 clamps them).
     * @param public_bytes The public key's 32 bytes, written.
     * @return Nothing; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<void> base(
        std::span<std::uint8_t const, 32> secret_key,
        std::span<std::uint8_t, 32> public_bytes) noexcept {
        return engine::base(secret_key, public_bytes);
    }

    /**
     * The shared secret of a secret key and a peer's public key, refused when it is all zero.
     *
     * @param secret_key 32 bytes.
     * @param peer_public_key 32 bytes.
     * @return 32 secret bytes; `weak_public_key` for a peer key of low order, whose shared secret
     * is all zero; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<secret<32>> agree(
        std::span<std::uint8_t const, 32> secret_key,
        std::span<std::uint8_t const, 32> peer_public_key) noexcept {
        secret<32> shared_bytes;
        auto const engine_done =
            engine::agree(secret_key, peer_public_key, shared_bytes.writable());
        if (!engine_done) {
            return engine_done.error();
        }
        // Every backend gives the same answer: libsodium refuses an all-zero result itself,
        // and the others are checked here, in constant time (design D8). Whether it is all zero
        // is public, since it is reported: marked so for the constant-time checks, and not const,
        // so that the branch reads it again after the mark (detail/declassify.hpp's tip).
        // NOLINTNEXTLINE(misc-const-correctness): see above
        bool all_zero = is_all_zero(shared_bytes.bytes());
        WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&all_zero, sizeof all_zero);
        if (all_zero) {
            return error::weak_public_key;
        }
        return shared_bytes;
    }

private:
    using engine = x25519_engine<families::x25519, Backend>;
};

/**
 * The bytes of an X25519 key pair, for crypto_kx, the boxes and the sealed box, which call
 * libsodium with them under their own guard, with no copy and no second guard (ruling P13).
 */
struct x25519_access;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::x25519 {

/**
 * An X25519 public key (RFC 7748): the 32 bytes of the u-coordinate, which a key pair's `agree`
 * takes.
 *
 * `from_bytes` checks the size alone (design R3): a key of low order is refused where it matters,
 * by `agree`, with `weak_public_key`, as RFC 7748 puts it. It holds nothing secret and is copied
 * freely; it is made only by `from_bytes` and by a key pair's `public_key()`.
 */
class public_key {
    friend struct detail::x25519_access;

public:
    /** The size of the key, in bytes. */
    static constexpr std::size_t public_key_size = 32;

    /**
     * Makes a public key from its 32 bytes, as RFC 7748 encodes it and WebCrypto's
     * `exportKey("raw")` writes it.
     *
     * @param key_bytes 32 bytes; nothing else is checked.
     * @return The public key; `invalid_public_key` for another size.
     */
    [[nodiscard]] static boost::system::result<public_key> from_bytes(
        std::span<std::uint8_t const> key_bytes) noexcept {
        if (key_bytes.size() != public_key_size) {
            return error::invalid_public_key;
        }
        public_key made_key;
        std::ranges::copy(key_bytes, made_key.bytes_.begin());
        return made_key;
    }

    /**
     * The key's bytes.
     *
     * @return 32 bytes.
     */
    [[nodiscard]] std::array<std::uint8_t, public_key_size> const& bytes() const noexcept {
        return bytes_;
    }

    /**
     * Compares two keys.
     *
     * @param other_key The other key.
     * @return True for the same 32 bytes.
     */
    [[nodiscard]] bool operator==(public_key const& other_key) const noexcept = default;

private:
    public_key() noexcept = default;

    std::array<std::uint8_t, public_key_size> bytes_{};
};

/**
 * An X25519 key pair (RFC 7748): its 32-byte secret key, wiped by every move and by the
 * destructor, and its public key, computed once when it is made.
 *
 * It agrees, with `agree(peer)`; it does not sign.
 *
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::x25519>`).
 */
template <class Backend = default_backend_t<families::x25519>>
class basic_keypair {
    using operations = detail::x25519_operations<Backend>;

    friend struct detail::x25519_access;
    // The asynchronous family's error completions make the empty object a move leaves.
    friend struct detail::async_access;

public:
    /** The family, for `supports_v`. */
    using family_type = families::x25519;
    /** The algorithm, for `supports_v`: the family's one name. */
    using name_type = families::x25519;
    /** The backend. */
    using backend_type = Backend;
    /** The public key's type, which `agree` takes. */
    using public_key_type = ::webcpp::crypto::curves::x25519::public_key;
    /** The size of the secret key `from_secret` takes and `secret()` gives. */
    static constexpr std::size_t secret_key_size = 32;

    /**
     * Makes a key pair from its secret key; its public key is computed here, once.
     *
     * @param secret_bytes 32 bytes; any 32 bytes are a secret key (RFC 7748 clamps them where
     * they are used).
     * @return The key pair; `invalid_key_size`; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> from_secret(
        std::span<std::uint8_t const> secret_bytes) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(!detail::asynchronous_backend_v<Backend>,
                      "webcpp::crypto: from_secret on this backend completes asynchronously: call "
                      "async_from_secret.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            if (secret_bytes.size() != secret_key_size) {
                return error::invalid_key_size;
            }
            basic_keypair made_pair;
            std::ranges::copy(secret_bytes, made_pair.secret_value_.writable().begin());
            auto const engine_done =
                operations::base(made_pair.secret_value_.bytes(), made_pair.public_bytes_);
            if (!engine_done) {
                return engine_done.error();
            }
            made_pair.keyed_ = true;
            return made_pair;
        }
    }

    /**
     * Makes a key pair from a fresh secret key, drawn from the system's generator.
     *
     * @return The key pair; `entropy_unavailable` when the system's generator fails or there is
     * none; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> generate() noexcept {
        detail::timing_guard const timing_scope;
        static_assert(!detail::asynchronous_backend_v<Backend>,
                      "webcpp::crypto: generate on this backend completes asynchronously: call "
                      "async_generate.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            crypto::secret<secret_key_size> drawn_secret;
            auto const entropy_drawn =
                random_device().fill(drawn_secret.writable());  // lint-world: the secret key
            if (!entropy_drawn) {
                // The generator's not_supported (an Emscripten audio worklet) is the same failure
                // for a key pair: one error to handle.
                return error::entropy_unavailable;
            }
            return from_secret(drawn_secret.bytes());
        }
    }

    /**
     * Makes a key pair from its secret key, asynchronously: `from_secret` run when the operation
     * is initiated, its result posted to `completion_executor`; the member form of the free
     * `crypto::async_from_secret<basic_keypair>`, with the same arguments, which calls it.
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param secret_bytes 32 bytes, the caller's until the completion.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, basic_keypair)`; on an error the key pair is empty, and
     * every member refuses with `invalid_state` (`invalid_key_size`, `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    static auto async_from_secret(Executor const& completion_executor,
                                  std::span<std::uint8_t const> secret_bytes,
                                  CompletionToken&& completion_token);

    /**
     * Makes a key pair from a fresh secret key, asynchronously: `generate` run when the operation
     * is initiated, its result posted to `completion_executor`; the member form of
     * `crypto::async_generate<basic_keypair>(completion_executor, completion_token)`, which calls
     * it.
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, basic_keypair)`; on an error the key pair is empty
     * (`entropy_unavailable`, `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    static auto async_generate(Executor const& completion_executor,
                               CompletionToken&& completion_token);

    /**
     * Moves the key pair; the source is wiped and empty.
     *
     * @param moved_from The key pair moved from.
     */
    basic_keypair(basic_keypair&& moved_from) noexcept
        : secret_value_(std::move(moved_from.secret_value_)),
          public_bytes_(moved_from.public_bytes_),
          keyed_(std::exchange(moved_from.keyed_, false)) {}

    /**
     * Moves over this key pair, whose secret key is wiped first.
     *
     * @param moved_from The key pair moved from, wiped and empty after.
     * @return This key pair.
     */
    basic_keypair& operator=(basic_keypair&& moved_from) noexcept {
        if (this != &moved_from) {
            secret_value_ = std::move(moved_from.secret_value_);
            public_bytes_ = moved_from.public_bytes_;
            keyed_ = std::exchange(moved_from.keyed_, false);
        }
        return *this;
    }

    /** Not copyable: a secret key has one owner. */
    basic_keypair(basic_keypair const&) = delete;
    /** Not copyable: a secret key has one owner. */
    basic_keypair& operator=(basic_keypair const&) = delete;

    /** Wipes the secret key. */
    ~basic_keypair() = default;

    /**
     * The public key, which a peer's `agree` takes: a copy of the one computed when the key pair
     * was made.
     *
     * @return The public key; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<public_key_type> public_key() const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        return public_key_type::from_bytes(public_bytes_);
    }

    /**
     * The secret key, for a program that keeps the key pair and makes it again with
     * `from_secret`, or exports it: a copy.
     *
     * @return 32 secret bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<crypto::secret<secret_key_size>> secret() const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        crypto::secret<secret_key_size> secret_copy;
        std::ranges::copy(secret_value_.bytes(), secret_copy.writable().begin());
        return secret_copy;
    }

    /**
     * The shared secret of this key pair and a peer's public key (RFC 7748's X25519), refused
     * when it is all zero, on every backend.
     *
     * The shared secret is not a key: a protocol hashes it into its keys, with HKDF for instance;
     * the derivation, its salt and its info are the protocol's.
     *
     * @param peer_key The peer's public key.
     * @return 32 secret bytes; `invalid_state` moved from; `weak_public_key` for a peer key of low
     * order, whose shared secret is all zero; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<crypto::secret<32>> agree(
        public_key_type const& peer_key) const noexcept {
        detail::timing_guard const timing_scope;
        static_assert(
            !detail::asynchronous_backend_v<Backend>,
            "webcpp::crypto: agree on this backend completes asynchronously: call async_agree.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            if (!keyed_) {
                return error::invalid_state;
            }
            return operations::agree(secret_value_.bytes(), peer_key.bytes());
        }
    }

    /**
     * The shared secret of this key pair and a peer's public key, asynchronously: `agree` run when
     * the operation is initiated, its result posted to `completion_executor`; the member form of
     * `crypto::async_agree(completion_executor, key_pair, peer_key, completion_token)`, which
     * calls it.
     *
     * The key pair and the peer's key are the caller's until the completion.
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param peer_key The peer's public key.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, crypto::secret<32>)`: the shared secret; on an error a
     * secret of zeros (`invalid_state`, `weak_public_key`, `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    auto async_agree(Executor const& completion_executor, public_key_type const& peer_key,
                     CompletionToken&& completion_token) const;

private:
    basic_keypair() noexcept = default;

    crypto::secret<secret_key_size> secret_value_;
    std::array<std::uint8_t, public_key_type::public_key_size> public_bytes_{};
    bool keyed_ = false;
};

/** The key pair on the default backend. */
using keypair = basic_keypair<>;

}  // namespace webcpp::crypto::curves::x25519

namespace webcpp::crypto::detail {

struct x25519_access {
    /**
     * A key pair's secret key, viewed: valid while the key pair lives and is not moved from.
     *
     * @tparam Backend The key pair's backend.
     * @param key_pair A key pair, not moved from (the caller checks).
     * @return Its 32 secret bytes.
     */
    template <class Backend>
    [[nodiscard]] static std::span<std::uint8_t const, 32> secret_bytes(
        curves::x25519::basic_keypair<Backend> const& key_pair) noexcept {
        return key_pair.secret_value_.bytes();
    }

    /**
     * A key pair's public key, viewed.
     *
     * @tparam Backend The key pair's backend.
     * @param key_pair A key pair.
     * @return Its public key's 32 bytes.
     */
    template <class Backend>
    [[nodiscard]] static std::span<std::uint8_t const, 32> public_bytes(
        curves::x25519::basic_keypair<Backend> const& key_pair) noexcept {
        return key_pair.public_bytes_;
    }
};

/**
 * X25519's engine on a backend whose header does not specialise it: the family's refusal,
 * which names what the program needs (`detail/capabilities.hpp`). Its functions are never
 * called: the refusal stops the build where the class is instantiated, and they keep the
 * compiler from adding errors of their own after it; they report `backend_failure`, so that a
 * path the refusal missed fails closed.
 */
template <class Name, class Backend>
struct x25519_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_X25519(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> base(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> agree(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace webcpp::crypto::detail

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_X25519_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_CURVES_X25519_HPP
