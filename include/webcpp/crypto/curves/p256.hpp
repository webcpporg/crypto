// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 P-256, NIST's curve of FIPS 186-5 (secp256r1): a key pair made from its 32-byte scalar or drawn
 from the system's generator, and a public key validated once, as SEC 1's uncompressed point.

 The family's default backend, BearSSL on every target, is included when the program links it;
 a program that uses the family without linking it stops where it calls it, with the Jamfile
 line that links it.

 @see "P-256", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_P256_HPP
#define WEBCPP_CRYPTO_CURVES_P256_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/p_curves.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: random_device draws generate()'s scalar
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto::curves::p256 {

/** The size of a secret key, the scalar d, big-endian. */
inline constexpr std::size_t secret_key_size = 32;
/** The size of a coordinate, x or y, big-endian. */
inline constexpr std::size_t coordinate_size = 32;
/** The size of a public key, SEC 1's uncompressed point 04 || x || y. */
inline constexpr std::size_t public_key_size = 65;
/** The size of the digest ECDSA signs, SHA-256's. */
inline constexpr std::size_t digest_size = 32;
/** The size of a signature, r || s (IEEE P1363, WebCrypto's form). */
inline constexpr std::size_t signature_size = 64;
/** The longest strict DER encoding of a signature. */
inline constexpr std::size_t max_der_size = 72;

/**
 * A P-256 public key, validated: a point on the curve, its coordinates below p, never the
 * identity, kept as SEC 1's uncompressed point.
 *
 * It holds nothing secret and is copied freely; it is made only by the functions that return
 * one, so that it is always valid: a peer's key is made once, where it arrives, and kept.
 *
 * @tparam Backend The backend that checks the point; by default the family's
 * (`default_backend_t<families::p256>`).
 */
template <class Backend = default_backend_t<families::p256>>
class basic_public_key {
    using engine = detail::p_curve_engine<families::p256, Backend>;

    friend struct detail::p_curve_access;

public:
    /** The family, for `supports_v`. */
    using family_type = families::p256;
    /** The algorithm, for `supports_v`. */
    using name_type = families::p256;
    /** The backend. */
    using backend_type = Backend;
    /** The size of the encoded point. */
    static constexpr std::size_t public_key_size = p256::public_key_size;
    /** The size of a coordinate. */
    static constexpr std::size_t coordinate_size = p256::coordinate_size;

    /**
     * Makes a public key from SEC 1's uncompressed point, as WebCrypto's `exportKey("raw")`
     * writes it.
     *
     * @param uncompressed_point 65 bytes: 04, x, y.
     * @return The public key; `invalid_public_key` for another size, another first byte (the
     * compressed form included), a coordinate not below p or a point off the curve.
     */
    [[nodiscard]] static boost::system::result<basic_public_key> make(
        std::span<std::uint8_t const> uncompressed_point) noexcept {
        detail::timing_guard const timing;
        if (uncompressed_point.size() != public_key_size || uncompressed_point[0] != 0x04) {
            return error::invalid_public_key;
        }
        return checked(uncompressed_point.template first<public_key_size>());
    }

    /**
     * Makes a public key from its two coordinates, as a JSON Web Key's `x` and `y` carry them.
     *
     * @param x 32 bytes, big-endian.
     * @param y 32 bytes, big-endian.
     * @return The public key; `invalid_public_key` for a coordinate not below p or a point off
     * the curve.
     */
    [[nodiscard]] static boost::system::result<basic_public_key> make(
        std::span<std::uint8_t const, coordinate_size> x,
        std::span<std::uint8_t const, coordinate_size> y) noexcept {
        detail::timing_guard const timing;
        std::array<std::uint8_t, public_key_size> point{0x04};
        std::ranges::copy(x, point.begin() + 1);
        std::ranges::copy(y, point.begin() + 1 + coordinate_size);
        return checked(point);
    }

    /**
     * The point, as WebCrypto's `exportKey("raw")` writes it.
     *
     * @return 65 bytes: 04, x, y.
     */
    [[nodiscard]] std::array<std::uint8_t, public_key_size> uncompressed() const noexcept {
        return point_;
    }

private:
    basic_public_key() noexcept = default;

    // The backend's check of a point whose size and first byte are checked, and the key made of
    // it: the work of both make, which hold their own guards.
    [[nodiscard]] static boost::system::result<basic_public_key> checked(
        std::span<std::uint8_t const, public_key_size> point) noexcept {
        if (!engine::valid_point(point)) {
            return error::invalid_public_key;
        }
        basic_public_key made;
        std::ranges::copy(point, made.point_.begin());
        return made;
    }

    std::array<std::uint8_t, public_key_size> point_{};
};

/** The public key on the default backend. */
using public_key = basic_public_key<>;

/**
 * A P-256 key pair: its secret scalar d, kept by the backend and wiped by every move and by the
 * destructor, and its public point d * G, computed once when it is made.
 *
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::p256>`).
 */
template <class Backend = default_backend_t<families::p256>>
class basic_keypair {
    using state_type = detail::p_curve_state<families::p256, Backend>;
    using engine = detail::p_curve_engine<families::p256, Backend>;
    using traits = detail::p_curve_traits<families::p256>;

public:
    /** The family, for `supports_v`. */
    using family_type = families::p256;
    /** The algorithm, for `supports_v`. */
    using name_type = families::p256;
    /** The backend. */
    using backend_type = Backend;
    /** The size of the secret scalar. */
    static constexpr std::size_t secret_key_size = p256::secret_key_size;
    /** The size of the public key, SEC 1's uncompressed point. */
    static constexpr std::size_t public_key_size = p256::public_key_size;

    /**
     * Makes a key pair from its secret scalar, as a program that kept `secret_scalar` loads it
     * again.
     *
     * @param secret_scalar 32 bytes, big-endian, not zero and below the group order n.
     * @return The key pair; `invalid_key_size`; `invalid_secret_key` for a scalar 0 or not below
     * n, refused before the backend; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> make(
        std::span<std::uint8_t const> secret_scalar) noexcept {
        detail::timing_guard const timing;
        if (secret_scalar.size() != secret_key_size) {
            return error::invalid_key_size;
        }
        auto const scalar = secret_scalar.template first<secret_key_size>();
        if (!detail::p_curve_scalar_valid(scalar, traits::order)) {
            return error::invalid_secret_key;
        }
        basic_keypair made;
        auto const keyed = engine::make(made.state_, scalar);
        if (!keyed) {
            return keyed.error();
        }
        made.keyed_ = true;
        return made;
    }

    /**
     * Makes a key pair from a fresh scalar, drawn from the system's generator until it is below
     * the group order (a draw is refused about once in 2^32).
     *
     * @return The key pair; `entropy_unavailable` when the system's generator fails or there is
     * none; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> generate() noexcept {
        detail::timing_guard const timing;
        secret<secret_key_size> scalar;
        random_device device;  // lint-world: the scalar
        do {
            if (!device.fill(scalar.writable())) {
                // The generator's not_supported (an Emscripten audio worklet) is the same failure
                // for a key pair: one error to handle.
                return error::entropy_unavailable;
            }
        } while (!detail::p_curve_scalar_valid(scalar.bytes(), traits::order));
        return make(scalar.bytes());
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

    /** Wipes the secret scalar. */
    ~basic_keypair() { engine::reset(state_); }

    /**
     * The public key, computed when the key pair was made.
     *
     * @return The public key; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<basic_public_key<Backend>> public_key() const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        auto key = detail::p_curve_access::blank<basic_public_key<Backend>>();
        engine::public_point(state_, detail::p_curve_access::point(key));
        return key;
    }

    /**
     * The secret scalar, for a program that keeps the key pair and makes it again with `make`.
     *
     * @return 32 secret bytes, big-endian; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<secret<secret_key_size>> secret_scalar() const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        secret<secret_key_size> scalar;
        engine::scalar(state_, scalar.writable());
        return scalar;
    }

private:
    basic_keypair() noexcept = default;

    state_type state_{};
    bool keyed_ = false;
};

/** The key pair on the default backend. */
using keypair = basic_keypair<>;

}  // namespace webcpp::crypto::curves::p256

namespace webcpp::crypto::detail {

/**
 * P-256's engine on a backend whose header does not specialise it: the family's refusal, which
 * names what the program needs (`detail/capabilities.hpp`). Its functions are never called: the
 * refusal stops the build where the class is instantiated, and they keep the compiler from adding
 * errors of their own after it; those that answer fail closed, `backend_failure` or `false`.
 */
template <class Backend>
struct p_curve_engine<families::p256, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_P256(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> make(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static bool valid_point(Arguments&&... /*arguments*/) noexcept {
        return false;
    }

    /** Never called. */
    template <class... Arguments>
    static void public_point(Arguments&&... /*arguments*/) noexcept {}

    /** Never called. */
    template <class... Arguments>
    static void scalar(Arguments&&... /*arguments*/) noexcept {}

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

// The default backend's engine, when the program links it (design D32): BearSSL on every target.
// Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_P256_BEARSSL) && defined(WEBCPP_CRYPTO_HAS_BEARSSL)
#include <webcpp/crypto/backends/bearssl.hpp>
#endif

#endif  // WEBCPP_CRYPTO_CURVES_P256_HPP
