// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Ed25519 signatures (RFC 8032): a key pair made from a 32-byte seed, signatures of 64 bytes,
 `key.sign(crypto::eddsa, message)`, and their verification,
 `crypto::verify(crypto::eddsa, signature, message, public_key)`, strict on libsodium; the
 conversion of a public key to X25519's; and Ed25519ph, the same signature over SHA-512 of a
 message given in pieces.

 The family's default backend, libsodium on every target, is included when the program links
 it; a program that uses the family without linking it stops where it calls it, with the
 Jamfile line that links it.

 @see "Ed25519", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_ED25519_HPP
#define WEBCPP_CRYPTO_CURVES_ED25519_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: random_device draws generate()'s seed
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>  // webcpp::hash::sha2_512, Ed25519ph's hash (design D1)

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::crypto::detail {

/**
 * What an Ed25519 key pair stores on a backend whose header does not specialise it: nothing,
 * since its engine refuses the backend where the family is called.
 */
template <class Name, class Backend>
struct ed25519_state {};

/** The work of Ed25519 on a backend; the primary refuses (defined at the end of this header). */
template <class Name, class Backend>
struct ed25519_engine;

/** What an Ed25519ph signer stores on a backend (see @ref ed25519_state). */
template <class Name, class Backend>
struct ed25519ph_state {};

/** The work of Ed25519ph on a backend; the primary refuses (defined at the end of this header). */
template <class Name, class Backend>
struct ed25519ph_engine;

/**
 * What reads a key pair's state for its PKCS#8, `curves::ed25519::encode_pkcs8`
 * (`curves/ed25519/formats.hpp` defines it).
 */
template <class Backend>
struct ed25519_keypair_access;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::ed25519 {

template <class Hash, class Backend>
class ph;

/**
 * An Ed25519 key pair (RFC 8032): its secret key, kept by the backend and wiped by every move
 * and by the destructor, and its public key.
 *
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::ed25519>`).
 */
template <class Backend = default_backend_t<families::ed25519>>
class basic_keypair {
    using state_type = detail::ed25519_state<families::ed25519, Backend>;
    using engine = detail::ed25519_engine<families::ed25519, Backend>;

    template <class, class>
    friend class ph;
    template <class>
    friend struct detail::ed25519_keypair_access;
    // The asynchronous family's error completions make the empty object a move leaves.
    friend struct detail::async_access;

public:
    /** The family, for `supports_v`. */
    using family_type = families::ed25519;
    /** The algorithm, for `supports_v`. */
    using name_type = families::ed25519;
    /** The backend. */
    using backend_type = Backend;
    /** The seed's size. */
    static constexpr std::size_t seed_size = 32;
    /** The public key's size. */
    static constexpr std::size_t public_key_size = 32;
    /** The signature's size. */
    static constexpr std::size_t signature_size = 64;

    /**
     * Makes a key pair from a seed, RFC 8032's secret key.
     *
     * @param seed 32 bytes.
     * @return The key pair; `invalid_key_size`; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> make(
        std::span<std::uint8_t const> seed) noexcept {
        detail::timing_guard const timing;
        if (seed.size() != seed_size) {
            return error::invalid_key_size;
        }
        basic_keypair made;
        auto const keyed = engine::make(made.state_, seed.template first<seed_size>());
        if (!keyed) {
            return keyed.error();
        }
        made.keyed_ = true;
        return made;
    }

    /**
     * Makes a key pair from a fresh seed, drawn from the system's generator.
     *
     * @return The key pair; `entropy_unavailable` when the system's generator fails or there is
     * none; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> generate() noexcept {
        detail::timing_guard const timing;
        secret<seed_size> seed;
        auto const drawn = random_device().fill(seed.writable());  // lint-world: the seed
        if (!drawn) {
            // The generator's not_supported (an Emscripten audio worklet) is the same failure
            // for a key pair: one error to handle.
            return error::entropy_unavailable;
        }
        return make(seed.bytes());
    }

    /**
     * Moves the key pair; the source is wiped and empty.
     *
     * @param other The key pair moved from.
     */
    basic_keypair(basic_keypair&& other) noexcept : keyed_(std::exchange(other.keyed_, false)) {
        state_ = other.state_;
        engine::reset(other.state_);
    }

    /**
     * Moves over this key pair, which is wiped first.
     *
     * @param other The key pair moved from, wiped and empty after.
     * @return This key pair.
     */
    basic_keypair& operator=(basic_keypair&& other) noexcept {
        if (this != &other) {
            engine::reset(state_);
            keyed_ = std::exchange(other.keyed_, false);
            state_ = other.state_;
            engine::reset(other.state_);
        }
        return *this;
    }

    /** Not copyable: a secret key has one owner. */
    basic_keypair(basic_keypair const&) = delete;
    /** Not copyable: a secret key has one owner. */
    basic_keypair& operator=(basic_keypair const&) = delete;

    /** Wipes the secret key. */
    ~basic_keypair() { engine::reset(state_); }

    /**
     * The public key.
     *
     * @return 32 bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> public_key() const noexcept {
        detail::timing_guard const timing;
        if (!keyed_) {
            return error::invalid_state;
        }
        std::array<std::uint8_t, 32> key{};
        engine::public_key(state_, key);
        return key;
    }

    /**
     * Signs a message with Ed25519 (RFC 8032's pure Ed25519: the message itself, of any length,
     * empty included, is signed; no digest is taken).
     *
     * @tparam Scheme `crypto::eddsa_t`; another scheme stops the build.
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`; a
     * `crypto::prehashed` marker, or anything else, stops the build (Ed25519ph is @ref ph).
     * @param scheme `crypto::eddsa`.
     * @param message Any bytes.
     * @return The 64-byte signature; `invalid_state` moved from; `backend_failure`.
     */
    template <class Scheme, class Input>
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        [[maybe_unused]] Scheme scheme, Input const& message) const noexcept {
        detail::timing_guard const timing;
        static_assert(std::is_same_v<Scheme, eddsa_t>,
                      "webcpp::crypto: an Ed25519 key signs with crypto::eddsa.");
        if constexpr (std::is_same_v<Scheme, eddsa_t>) {
            detail::check_input<Scheme, Input, Backend>();
            if constexpr (detail::input_valid_v<Scheme, Input, Backend>) {
                return signed_message(detail::message_bytes(message));
            } else {
                // Never compiled into a program: check_input stopped the build.
                return error::backend_failure;
            }
        } else {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        }
    }

    /**
     * The X25519 secret key of this key pair, RFC 7748's form of the clamped first half of the
     * seed's SHA-512.
     *
     * @return 32 secret bytes; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<secret<32>> x25519_secret() const noexcept {
        detail::timing_guard const timing;
        if (!keyed_) {
            return error::invalid_state;
        }
        secret<32> converted;
        auto const done = engine::x25519_secret(state_, converted.writable());
        if (!done) {
            return done.error();
        }
        return converted;
    }

private:
    basic_keypair() noexcept = default;

    // The work of sign, which holds the guard: the signature of the message's bytes.
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> signed_message(
        std::span<std::uint8_t const> message) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        std::array<std::uint8_t, 64> signature{};
        auto const signed_bytes = engine::sign(state_, message, signature);
        if (!signed_bytes) {
            return signed_bytes.error();
        }
        return signature;
    }

    state_type state_{};
    bool keyed_ = false;
};

/** The key pair on the default backend. */
using keypair = basic_keypair<>;

/**
 * The type of the verification policy `strict`.
 *
 * Its explicit default constructor keeps `{}` from standing for a policy.
 */
struct strict_t {
    /** Makes the tag. */
    explicit strict_t() = default;
};

/**
 * Ed25519 verification as libsodium does it: `S` below the group order, `A` and `R` canonical,
 * neither of small order (design D31); `crypto::verify`'s policy by default.
 */
inline constexpr strict_t strict{};

/**
 * The X25519 public key of an Ed25519 public key (the birational map from edwards25519 to
 * Curve25519), so that a peer known by its Ed25519 key can be agreed with by
 * `curves::x25519::agree`; the key pair's own side is `basic_keypair::x25519_secret`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param ed25519_public_key 32 bytes.
 * @return 32 bytes; `invalid_public_key` for a key of another size, not canonical, not on the
 * curve or of small order.
 */
template <class Backend = default_backend_t<families::ed25519>>
[[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> to_x25519_public(
    std::span<std::uint8_t const> ed25519_public_key) noexcept {
    detail::timing_guard const timing;
    if (ed25519_public_key.size() != 32) {
        return error::invalid_public_key;
    }
    std::array<std::uint8_t, 32> converted{};
    auto const done = detail::ed25519_engine<families::ed25519, Backend>::to_x25519_public(
        ed25519_public_key.first<32>(), converted);
    if (!done) {
        return done.error();
    }
    return converted;
}

/**
 * Ed25519ph (RFC 8032 section 5.1), the Ed25519 signature of a message's SHA-512, given in
 * pieces.
 *
 * A large message need not be held whole: the signer is begun, updated with each piece, then
 * signs with a key pair or verifies with a public key, either of which ends the message. Its
 * state is wiped by every move, by the end of a message and by the destructor.
 *
 * Its signature is not Ed25519's of the same message: a verifier is told which of the two a
 * protocol uses.
 *
 * @tparam Hash `webcpp::hash::sha2_512`, which RFC 8032 fixes; any other is refused.
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::ed25519>`).
 */
template <class Hash, class Backend = default_backend_t<families::ed25519>>
class ph {
    // clang-format off
    static_assert(std::is_same_v<Hash, ::webcpp::hash::sha2_512>, "webcpp::crypto: Ed25519ph is defined over SHA-512 (RFC 8032 section 5.1); name curves::ed25519::ph<webcpp::hash::sha2_512>.");
    // clang-format on

    using state_type = detail::ed25519ph_state<tags::ed25519ph, Backend>;
    using engine = detail::ed25519ph_engine<tags::ed25519ph, Backend>;

public:
    /** The family, for `supports_v`. */
    using family_type = families::ed25519;
    /** The algorithm, for `supports_v`. */
    using name_type = tags::ed25519ph;
    /** The backend. */
    using backend_type = Backend;
    /** The hash, SHA-512. */
    using hash_type = Hash;
    /** The signature's size. */
    static constexpr std::size_t signature_size = 64;

    /**
     * Begins a message.
     *
     * @return The signer, ready for the message's pieces; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<ph> begin() noexcept {
        detail::timing_guard const timing;
        ph begun;
        auto const started = engine::begin(begun.state_);
        if (!started) {
            return started.error();
        }
        begun.begun_ = true;
        return begun;
    }

    /**
     * Moves the signer and its message; the source is wiped and ended.
     *
     * @param other The signer moved from.
     */
    ph(ph&& other) noexcept : begun_(std::exchange(other.begun_, false)) {
        state_ = other.state_;
        engine::reset(other.state_);
    }

    /**
     * Moves over this signer, whose message is wiped first.
     *
     * @param other The signer moved from, wiped and ended after.
     * @return This signer.
     */
    ph& operator=(ph&& other) noexcept {
        if (this != &other) {
            engine::reset(state_);
            begun_ = std::exchange(other.begun_, false);
            state_ = other.state_;
            engine::reset(other.state_);
        }
        return *this;
    }

    /** Not copyable: the state of a message has one owner. */
    ph(ph const&) = delete;
    /** Not copyable: the state of a message has one owner. */
    ph& operator=(ph const&) = delete;

    /** Wipes the state of the message. */
    ~ph() { engine::reset(state_); }

    /**
     * Adds a piece of the message.
     *
     * @param piece Any bytes, empty included.
     * @return Nothing; `invalid_state` once the message is signed or verified, or moved from.
     */
    [[nodiscard]] boost::system::result<void> update(std::span<std::uint8_t const> piece) noexcept {
        detail::timing_guard const timing;
        if (!begun_) {
            return error::invalid_state;
        }
        engine::update(state_, piece);
        return {};
    }

    /**
     * Signs the message given, which it ends.
     *
     * @param key The key pair, of the same backend.
     * @return The 64-byte signature; `invalid_state` once the message is ended, or moved from,
     * or with a moved-from key pair; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign(
        basic_keypair<Backend> const& key) noexcept {
        detail::timing_guard const timing;
        if (!begun_ || !key.keyed_) {
            return error::invalid_state;
        }
        std::array<std::uint8_t, 64> signature{};
        auto const signed_message = engine::sign(state_, key.state_, signature);
        end();
        if (!signed_message) {
            return signed_message.error();
        }
        return signature;
    }

    /**
     * Verifies a signature of the message given, which it ends, strictly (design D31).
     *
     * @param signature 64 bytes.
     * @param public_key 32 bytes.
     * @return Nothing; `invalid_state` once the message is ended, or moved from;
     * `invalid_signature` for a signature of another size, then `invalid_public_key` for a key of
     * another size, so that the arguments given in the other order are refused as a signature;
     * `invalid_signature`.
     */
    [[nodiscard]] boost::system::result<void> verify(
        std::span<std::uint8_t const> signature,
        std::span<std::uint8_t const> public_key) noexcept {
        detail::timing_guard const timing;
        if (!begun_) {
            return error::invalid_state;
        }
        boost::system::result<void> verified = error::invalid_signature;
        if (signature.size() == 64) {
            verified = public_key.size() == 32
                           ? engine::verify(state_, public_key.first<32>(), signature.first<64>())
                           : boost::system::result<void>(error::invalid_public_key);
        }
        end();
        return verified;
    }

private:
    ph() noexcept = default;

    // The message is ended: its state is wiped, and only begin makes another.
    void end() noexcept {
        engine::reset(state_);
        begun_ = false;
    }

    state_type state_{};
    bool begun_ = false;
};

}  // namespace webcpp::crypto::curves::ed25519

namespace webcpp::crypto {

/**
 * Verifies an Ed25519 signature (RFC 8032's pure Ed25519) under a verification policy (design
 * D31).
 *
 * The signature comes first, as in every `verify`: the arguments of the order before it, a
 * 32-byte key where the signature goes, are refused as a signature of another size.
 *
 * @tparam Backend The backend; by default the family's.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`; a
 * `crypto::prehashed` marker, or anything else, stops the build.
 * @tparam Policy `curves::ed25519::strict_t` (libsodium's rules), the only policy declared;
 * anything else stops the build.
 * @param scheme `crypto::eddsa`.
 * @param signature 64 bytes.
 * @param message The signed bytes.
 * @param public_key 32 bytes.
 * @param policy `curves::ed25519::strict`, the default.
 * @return Nothing; `invalid_signature` for a signature of another size, then
 * `invalid_public_key` for a key of another size; `invalid_signature` for a signature that does
 * not verify.
 */
template <class Backend = default_backend_t<families::ed25519>, class Input,
          class Policy = curves::ed25519::strict_t>
[[nodiscard]] boost::system::result<void> verify(
    [[maybe_unused]] eddsa_t scheme, std::span<std::uint8_t const> signature, Input const& message,
    std::span<std::uint8_t const> public_key, [[maybe_unused]] Policy policy = Policy{}) noexcept {
    detail::timing_guard const timing;
    static_assert(std::is_same_v<Policy, curves::ed25519::strict_t>,
                  "webcpp::crypto: Ed25519's only verification policy is curves::ed25519::strict.");
    detail::check_input<eddsa_t, Input, Backend>();
    if constexpr (detail::input_valid_v<eddsa_t, Input, Backend>) {
        if (signature.size() != 64) {
            return error::invalid_signature;
        }
        if (public_key.size() != 32) {
            return error::invalid_public_key;
        }
        return detail::ed25519_engine<families::ed25519, Backend>::verify(
            public_key.first<32>(), detail::message_bytes(message), signature.first<64>());
    } else {
        // Never compiled into a program: check_input stopped the build.
        return error::invalid_signature;
    }
}

}  // namespace webcpp::crypto

namespace webcpp::crypto::detail {

/**
 * An Ed25519 key pair signs with `eddsa`.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
inline constexpr bool signs_with_v<curves::ed25519::basic_keypair<Backend>, eddsa_t> = true;

/**
 * An Ed25519 key pair's backend.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
struct key_backend<curves::ed25519::basic_keypair<Backend>> {
    /** The backend. */
    using type = Backend;
};

/**
 * An Ed25519 public key, its 32 bytes, verifies `eddsa`: any bytes that convert to
 * `std::span<std::uint8_t const>`, whose size `verify` checks; its backend is `void`, the
 * primary `key_backend`'s.
 *
 * @tparam Key The public key's type.
 */
template <class Key>
    requires std::is_convertible_v<Key const&, std::span<std::uint8_t const>>
inline constexpr bool verifies_with_v<Key, eddsa_t> = true;

/**
 * `crypto::verify` of `eddsa` against bytes is Ed25519's, so that the catch-all steps aside.
 *
 * @tparam Key The public key's type.
 */
template <class Key>
    requires std::is_convertible_v<Key const&, std::span<std::uint8_t const>>
inline constexpr bool has_verifier_v<eddsa_t, Key> = true;

/**
 * Ed25519's engine on a backend whose header does not specialise it: the family's refusal,
 * which names what the program needs (`detail/capabilities.hpp`). Its functions are never
 * called: the refusal stops the build where the class is instantiated, and they keep the
 * compiler from adding errors of their own after it; those that return report
 * `backend_failure`, so that a path the refusal missed fails closed.
 */
template <class Name, class Backend>
struct ed25519_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_ED25519(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> make(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void public_key(Arguments&&... /*arguments*/) noexcept {}

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> sign(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> verify(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> x25519_secret(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> to_x25519_public(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

/** Ed25519ph's engine on a backend whose header does not specialise it (see @ref ed25519_engine).
 */
template <class Name, class Backend>
struct ed25519ph_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_ED25519(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> begin(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void update(Arguments&&... /*arguments*/) noexcept {}

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> sign(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> verify(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

// The default backend's engines, when the program links it (design D32): libsodium on every
// target. Its header specialises them for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_ED25519_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_CURVES_ED25519_HPP
