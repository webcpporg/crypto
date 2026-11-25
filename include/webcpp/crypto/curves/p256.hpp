// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 P-256, NIST's curve of FIPS 186-5 (secp256r1): a key pair made from its 32-byte scalar, which
 `secret()` gives back, or drawn from the system's generator, and a public key validated once, as
 SEC 1's uncompressed point;
 ECDSA over SHA-256 with RFC 6979's nonce, `key.sign(crypto::ecdsa_sha256, input)` and
 `crypto::verify(crypto::ecdsa_sha256, signature, input, public_key)`, the input a message, hashed
 inside, or `crypto::prehashed{digest}`, the signature a `curves::p256::ecdsa_signature`: signing
 gives low S, verification accepts high and low S; the signature's DER form, and low S as two
 functions, `normalize_low_s` and `is_low_s`;
 ECDH's `agree`, the shared point's raw x coordinate, as WebCrypto's `deriveBits` gives it.

 The family's default backend, BearSSL on every target, is included when the program links it;
 a program that uses the family without linking it stops where it calls it, with the Jamfile
 line that links it.

 @see "P-256", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_P256_HPP
#define WEBCPP_CRYPTO_CURVES_P256_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/p_curves.hpp>
#include <webcpp/crypto/detail/signature.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: random_device draws generate()'s scalar
#include <webcpp/crypto/signing.hpp>
#include <webcpp/secure/secret.hpp>
#include <webcpp/secure/timing_guard.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
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

}  // namespace webcpp::crypto::curves::p256

namespace webcpp::crypto::detail {

/** The tag of `curves::p256::ecdsa_signature`. */
struct p256_ecdsa_signature_tag {
    /** No recovery id. */
    static constexpr bool recoverable = false;
};

/**
 * Verifies an ECDSA signature over SHA-256 with a P-256 point on `Backend`: the work of
 * `basic_public_key::verify` and of `crypto::verify` of `ecdsa_sha256`, which hold the guard.
 *
 * @tparam Backend The key's backend.
 * @tparam Input A message or `crypto::prehashed<32>`; anything else stops the build.
 * @param signature_bytes The signature's 64 bytes, r then s.
 * @param signing_input The signed message, hashed with SHA-256 here, or the marker of its digest.
 * @param point_bytes The public key's point, validated when the key was made.
 * @return Nothing; `invalid_signature` for a signature out of range or that does not verify.
 */
template <class Backend, class Input>
[[nodiscard]] boost::system::result<void> p256_verify(
    std::span<std::uint8_t const, curves::p256::signature_size> signature_bytes,
    Input const& signing_input,
    std::span<std::uint8_t const, curves::p256::public_key_size> point_bytes) noexcept {
    check_input<ecdsa_sha256_t, Input, Backend>();
    if constexpr (input_valid_v<ecdsa_sha256_t, Input, Backend>) {
        using engine = p_curve_engine<families::p256, Backend>;
        std::array<std::uint8_t, curves::p256::digest_size> digest_bytes{};
        if constexpr (is_prehashed_v<Input>) {
            std::ranges::copy(signing_input.digest, digest_bytes.begin());
        } else {
            digest_bytes = sha256_of(message_bytes(signing_input));
        }
        if (!p_curve_signature_in_range<families::p256>(signature_bytes)) {
            return error::invalid_signature;
        }
        if (!engine::verify(point_bytes, digest_bytes, signature_bytes)) {
            return error::invalid_signature;
        }
        return {};
    } else {
        // Never compiled into a program: check_input stopped the build.
        return error::invalid_signature;
    }
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::p256 {

/**
 * A P-256 ECDSA signature, 64 bytes, r then s: what `sign(crypto::ecdsa_sha256, ...)` gives and
 * `crypto::verify(crypto::ecdsa_sha256, ...)` takes.
 *
 * Each of r and s is 32 bytes big-endian (IEEE P1363, WebCrypto's form). `from_bytes` checks the
 * size alone; whether r and s are in range, and s low, is verification's and `normalize_low_s`'s
 * judgment.
 */
using ecdsa_signature = detail::basic_signature<detail::p256_ecdsa_signature_tag, signature_size>;

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
    [[nodiscard]] static boost::system::result<basic_public_key> from_bytes(
        std::span<std::uint8_t const> uncompressed_point) noexcept {
        secure::timing_guard const timing_scope;
        if (uncompressed_point.size() != public_key_size || uncompressed_point[0] != 0x04) {
            return error::invalid_public_key;
        }
        return checked(uncompressed_point.template first<public_key_size>());
    }

    /**
     * Makes a public key from its two coordinates, as a JSON Web Key's `x` and `y` carry them.
     *
     * @param x_coordinate 32 bytes, big-endian.
     * @param y_coordinate 32 bytes, big-endian.
     * @return The public key; `invalid_public_key` for a coordinate not below p or a point off
     * the curve.
     */
    [[nodiscard]] static boost::system::result<basic_public_key> from_coordinates(
        std::span<std::uint8_t const, coordinate_size> x_coordinate,
        std::span<std::uint8_t const, coordinate_size> y_coordinate) noexcept {
        secure::timing_guard const timing_scope;
        std::array<std::uint8_t, public_key_size> point_bytes{0x04};
        std::ranges::copy(x_coordinate, point_bytes.begin() + 1);
        std::ranges::copy(y_coordinate, point_bytes.begin() + 1 + coordinate_size);
        return checked(point_bytes);
    }

    /**
     * The point, as WebCrypto's `exportKey("raw")` writes it.
     *
     * @return 65 bytes: 04, x, y.
     */
    [[nodiscard]] std::array<std::uint8_t, public_key_size> uncompressed() const noexcept {
        return point_;
    }

    /**
     * Verifies an ECDSA signature over SHA-256 with this key:
     * `crypto::verify(crypto::ecdsa_sha256, signature_value, signing_input, key)`, of which it is
     * the member form, with the same work, results and refusals.
     *
     * A high S and a low S are both accepted, as FIPS 186-5 and WebCrypto accept them; a protocol
     * that requires low S checks `curves::p256::is_low_s` too.
     *
     * @tparam Scheme `crypto::ecdsa_sha256_t`; another scheme stops the build.
     * @tparam Signature `curves::p256::ecdsa_signature`; another type, bytes included, stops the
     * build.
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
     * empty included, or `crypto::prehashed<32>`; anything else stops the build.
     * @param signing_scheme `crypto::ecdsa_sha256`.
     * @param signature_value The signature, r then s (IEEE P1363, WebCrypto's form); bytes from a
     * peer are made into one by `curves::p256::ecdsa_signature::from_bytes`.
     * @param signing_input The signed message, hashed with SHA-256 inside the call; or
     * `crypto::prehashed{digest}`, its 32-byte SHA-256 digest.
     * @return Nothing; `invalid_signature` for an r or an s that is 0 or not below n, and a
     * signature that does not verify.
     */
    template <class Scheme, class Signature, class Input>
    [[nodiscard]] boost::system::result<void> verify([[maybe_unused]] Scheme signing_scheme,
                                                     Signature const& signature_value,
                                                     Input const& signing_input) const noexcept {
        secure::timing_guard const timing_scope;
        static_assert(std::is_same_v<Scheme, ecdsa_sha256_t>,
                      "webcpp::crypto: a P-256 public key verifies crypto::ecdsa_sha256.");
        static_assert(!detail::asynchronous_backend_v<Backend>,
                      "webcpp::crypto: verify on this backend completes asynchronously: call "
                      "async_verify.");
        if constexpr (std::is_same_v<Scheme, ecdsa_sha256_t> &&
                      !detail::asynchronous_backend_v<Backend>) {
            return detail::p256_verify<Backend>(
                detail::checked_signature_bytes<ecdsa_signature, ecdsa_sha256_t>(signature_value),
                signing_input, point_);
        } else {
            // Never compiled into a program: an assertion above stopped the build.
            return error::invalid_signature;
        }
    }

    /**
     * Verifies an ECDSA signature over SHA-256 with this key, asynchronously: `verify` run when the
     * operation is initiated, its result posted to `completion_executor`; the member form of the
     * free `crypto::async_verify`, with the same arguments and this key, which calls it.
     *
     * The key and the bytes the input views are the caller's until the completion; the signature
     * is copied.
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam Scheme `crypto::ecdsa_sha256_t`; another scheme stops the build.
     * @tparam Signature `curves::p256::ecdsa_signature`; another type, bytes included, stops the
     * build.
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
     * empty included, or `crypto::prehashed<32>`; anything else stops the build.
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param signing_scheme `crypto::ecdsa_sha256`.
     * @param signature_value The signature, r then s (IEEE P1363, WebCrypto's form).
     * @param signing_input The signed message, or `crypto::prehashed{digest}`, its 32-byte SHA-256
     * digest.
     * @param completion_token The completion token, of signature `void(boost::system::error_code)`:
     * `invalid_signature` for an r or an s that is 0 or not below n, and one that does not verify.
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class Scheme, class Signature, class Input, class CompletionToken>
    auto async_verify(Executor const& completion_executor, Scheme signing_scheme,
                      Signature const& signature_value, Input const& signing_input,
                      CompletionToken&& completion_token) const;

    /**
     * Whether two keys are the same point.
     *
     * @param other_key The other key.
     * @return True for the same 65 bytes.
     */
    [[nodiscard]] bool operator==(basic_public_key const& other_key) const noexcept = default;

private:
    basic_public_key() noexcept = default;

    // The backend's check of a point whose size and first byte are checked, and the key made of
    // it: the work of `from_bytes` and `from_coordinates`, which hold their own guards.
    [[nodiscard]] static boost::system::result<basic_public_key> checked(
        std::span<std::uint8_t const, public_key_size> point_bytes) noexcept {
        if (!engine::valid_point(point_bytes)) {
            return error::invalid_public_key;
        }
        basic_public_key made_key;
        std::ranges::copy(point_bytes, made_key.point_.begin());
        return made_key;
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

    // The asynchronous family's error completions make the empty object a move leaves.
    friend struct detail::async_access;

public:
    /** The family, for `supports_v`. */
    using family_type = families::p256;
    /** The algorithm, for `supports_v`. */
    using name_type = families::p256;
    /** The backend. */
    using backend_type = Backend;
    /** The public key's type, which `crypto::verify` and `agree` take. */
    using public_key_type = basic_public_key<Backend>;
    /** The size of the secret scalar, which `from_secret` takes and `secret()` gives. */
    static constexpr std::size_t secret_key_size = p256::secret_key_size;
    /** The size of the public key, SEC 1's uncompressed point. */
    static constexpr std::size_t public_key_size = p256::public_key_size;

    /**
     * Makes a key pair from its secret scalar, as a program that kept `secret()` loads it again.
     *
     * @param secret_scalar 32 bytes, big-endian, not zero and below the group order n.
     * @return The key pair; `invalid_key_size`; `invalid_secret_key` for a scalar 0 or not below
     * n, refused before the backend; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> from_secret(
        std::span<std::uint8_t const> secret_scalar) noexcept {
        secure::timing_guard const timing_scope;
        static_assert(!detail::asynchronous_backend_v<Backend>,
                      "webcpp::crypto: from_secret on this backend completes asynchronously: call "
                      "async_from_secret.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            if (secret_scalar.size() != secret_key_size) {
                return error::invalid_key_size;
            }
            auto const scalar_bytes = secret_scalar.template first<secret_key_size>();
            if (!detail::p_curve_scalar_valid(scalar_bytes, traits::order)) {
                return error::invalid_secret_key;
            }
            basic_keypair made_pair;
            auto const engine_keyed = engine::import_secret(made_pair.state_, scalar_bytes);
            if (!engine_keyed) {
                return engine_keyed.error();
            }
            made_pair.keyed_ = true;
            return made_pair;
        }
    }

    /**
     * Makes a key pair from a fresh scalar, drawn from the system's generator until it is below
     * the group order (a draw is refused about once in 2^32).
     *
     * @return The key pair; `entropy_unavailable` when the system's generator fails or there is
     * none; `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> generate() noexcept {
        secure::timing_guard const timing_scope;
        static_assert(!detail::asynchronous_backend_v<Backend>,
                      "webcpp::crypto: generate on this backend completes asynchronously: call "
                      "async_generate.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            secure::secret<secret_key_size> scalar_bytes;
            random_device random_source;  // lint-world: the scalar
            do {
                if (!random_source.fill(scalar_bytes.writable())) {
                    // The generator's not_supported (an Emscripten audio worklet) is the same
                    // failure for a key pair: one error to handle.
                    return error::entropy_unavailable;
                }
            } while (!detail::p_curve_scalar_valid(scalar_bytes.bytes(), traits::order));
            return from_secret(scalar_bytes.bytes());
        }
    }

    /**
     * Makes a key pair from its secret scalar, asynchronously: `from_secret` run when the operation
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
     * @param secret_scalar 32 bytes, big-endian, the caller's until the completion.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, basic_keypair)`; on an error the key pair is empty, and
     * every member refuses with `invalid_state` (`invalid_key_size`, `invalid_secret_key`,
     * `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    static auto async_from_secret(Executor const& completion_executor,
                                  std::span<std::uint8_t const> secret_scalar,
                                  CompletionToken&& completion_token);

    /**
     * Makes a key pair from a fresh scalar, asynchronously: `generate` run when the operation is
     * initiated, its result posted to `completion_executor`; the member form of
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
        : keyed_(std::exchange(moved_from.keyed_, false)) {
        state_ = moved_from.state_;
        engine::reset(moved_from.state_);
    }

    /**
     * Moves over this key pair, which is wiped first.
     *
     * @param moved_from The key pair moved from, wiped and empty after.
     * @return This key pair.
     */
    basic_keypair& operator=(basic_keypair&& moved_from) noexcept {
        if (this != &moved_from) {
            engine::reset(state_);
            keyed_ = std::exchange(moved_from.keyed_, false);
            state_ = moved_from.state_;
            engine::reset(moved_from.state_);
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
        auto made_key = detail::p_curve_access::blank<basic_public_key<Backend>>();
        engine::public_point(state_, detail::p_curve_access::point(made_key));
        return made_key;
    }

    /**
     * The secret scalar, for a program that keeps the key pair and makes it again with
     * `from_secret`.
     *
     * @return 32 secret bytes, big-endian; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<secure::secret<secret_key_size>> secret() const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        secure::secret<secret_key_size> scalar_bytes;
        engine::scalar(state_, scalar_bytes.writable());
        return scalar_bytes;
    }

    /**
     * Signs with ECDSA over SHA-256 and RFC 6979's deterministic nonce (no random number is
     * drawn: the same key and input give the same signature), S always low, at most (n - 1) / 2,
     * as libsecp256k1 signs: the signature is normalized after it is made.
     *
     * @tparam Scheme `crypto::ecdsa_sha256_t`; another scheme stops the build.
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
     * empty included, or `crypto::prehashed<32>`; anything else stops the build.
     * @param signing_scheme `crypto::ecdsa_sha256`.
     * @param signing_input The message, hashed with SHA-256 inside the call, as WebCrypto's ECDSA
     * with SHA-256 hashes it; or `crypto::prehashed{digest}`, its 32-byte SHA-256 digest, signed as
     * given.
     * @return The signature, `curves::p256::ecdsa_signature`, r then s (IEEE P1363, WebCrypto's
     * form); `invalid_state` moved from; `backend_failure`, which a valid key pair cannot cause.
     */
    template <class Scheme, class Input>
    [[nodiscard]] boost::system::result<detail::signature_of_t<basic_keypair, Scheme>> sign(
        [[maybe_unused]] Scheme signing_scheme, Input const& signing_input) const noexcept {
        secure::timing_guard const timing_scope;
        static_assert(std::is_same_v<Scheme, ecdsa_sha256_t>,
                      "webcpp::crypto: a P-256 key signs with crypto::ecdsa_sha256.");
        static_assert(!detail::asynchronous_backend_v<Backend>,
                      "webcpp::crypto: sign on this backend completes asynchronously: call "
                      "async_sign.");
        if constexpr (std::is_same_v<Scheme, ecdsa_sha256_t> &&
                      !detail::asynchronous_backend_v<Backend>) {
            detail::check_input<Scheme, Input, Backend>();
            if constexpr (detail::input_valid_v<Scheme, Input, Backend>) {
                if constexpr (detail::is_prehashed_v<Input>) {
                    return signed_digest(signing_input.digest);
                } else {
                    return signed_digest(detail::sha256_of(detail::message_bytes(signing_input)));
                }
            } else {
                // Never compiled into a program: check_input stopped the build.
                return error::backend_failure;
            }
        } else {
            // Never compiled into a program: an assertion above stopped the build.
            return error::backend_failure;
        }
    }

    /**
     * Signs with ECDSA over SHA-256, asynchronously: `sign` run when the operation is initiated,
     * its result posted to `completion_executor`; the member form of the free `crypto::async_sign`,
     * with the same arguments and this key pair, which calls it.
     *
     * The scheme and the input are checked as `crypto::can_sign` checks them, before anything
     * else. The key pair and the bytes the input views are the caller's until the completion.
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam Scheme `crypto::ecdsa_sha256_t`; another scheme stops the build.
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
     * empty included, or `crypto::prehashed<32>`; anything else stops the build.
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param signing_scheme `crypto::ecdsa_sha256`.
     * @param signing_input The message, hashed with SHA-256, or `crypto::prehashed{digest}`.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, curves::p256::ecdsa_signature)`: r then s, S low; on an
     * error the signature of zeros (`invalid_state`, `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class Scheme, class Input, class CompletionToken>
    auto async_sign(Executor const& completion_executor, Scheme signing_scheme,
                    Input const& signing_input, CompletionToken&& completion_token) const;

    /**
     * ECDH with a peer's public key: the x coordinate of the shared point d * Q, raw, as
     * WebCrypto's `deriveBits` with ECDH on P-256 gives its 256 bits.
     *
     * The x coordinate is not a key: its bits are not uniform. A protocol hashes it into its keys,
     * with HKDF for instance; the derivation, its salt and its info are the protocol's.
     *
     * @param peer_key The peer's public key, validated when it was made.
     * @return 32 secret bytes, big-endian; `invalid_state` moved from; `backend_failure`, which a
     * valid key pair and a valid public key cannot cause.
     */
    [[nodiscard]] boost::system::result<secure::secret<coordinate_size>> agree(
        basic_public_key<Backend> const& peer_key) const noexcept {
        secure::timing_guard const timing_scope;
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
            secure::secret<coordinate_size> shared_bytes;
            auto const derive_result = engine::ecdh_x(
                state_, detail::p_curve_access::point(peer_key), shared_bytes.writable());
            if (!derive_result) {
                return derive_result.error();
            }
            return shared_bytes;
        }
    }

    /**
     * ECDH with a peer's public key, asynchronously: `agree` run when the operation is initiated,
     * its result posted to `completion_executor`; the member form of
     * `crypto::async_agree(completion_executor, key_pair, peer_key, completion_token)`, which calls
     * it.
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
     * @param peer_key The peer's public key, validated when it was made.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, secure::secret<32>)`: the shared x, big-endian; on an error
     * a secret of zeros (`invalid_state`, `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    auto async_agree(Executor const& completion_executor, basic_public_key<Backend> const& peer_key,
                     CompletionToken&& completion_token) const;

private:
    basic_keypair() noexcept = default;

    // The work of sign, which holds the guard: RFC 6979's signature of a digest, made low S in
    // constant time: n - s is computed always and selected with a mask, with no branch on s and
    // nothing declassified, so that the signature stays as secret to a constant-time checker as
    // the engine made it.
    [[nodiscard]] boost::system::result<ecdsa_signature> signed_digest(
        std::span<std::uint8_t const, digest_size> digest_bytes) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        std::array<std::uint8_t, signature_size> signature_bytes{};
        auto const sign_result = engine::sign(state_, digest_bytes, signature_bytes);
        if (!sign_result) {
            return sign_result.error();
        }
        auto const s_value = std::span<std::uint8_t const, signature_size>(signature_bytes)
                                 .template last<coordinate_size>();
        std::array<std::uint8_t, coordinate_size> negated_s{};
        detail::p_curve_negate_scalar<families::p256>(s_value, negated_s);
        unsigned const high_mask = detail::p_curve_high_s_mask<families::p256>(s_value);
        for (std::size_t byte_index = 0; byte_index < coordinate_size; ++byte_index) {
            auto& s_byte = signature_bytes[coordinate_size + byte_index];
            unsigned const kept_byte = s_byte;
            s_byte = static_cast<std::uint8_t>(
                kept_byte ^ (high_mask & (kept_byte ^ unsigned{negated_s[byte_index]})));
        }
        return detail::signature_access::of<ecdsa_signature>(signature_bytes);
    }

    state_type state_{};
    bool keyed_ = false;
};

/** The key pair on the default backend. */
using keypair = basic_keypair<>;

/**
 * Encodes a signature as strict DER, the ECDSA-Sig-Value SEQUENCE of two INTEGERs that X.509
 * and OpenSSL carry.
 *
 * @tparam Backend The backend that encodes; by default the family's.
 * @param signature_value The signature.
 * @param der_output At least `max_der_size` bytes, whatever this signature's length; nothing is
 * written on an error.
 * @return The number of bytes written, 8 to `max_der_size`; `invalid_input_size` when
 * `der_output` is shorter than `max_der_size`; `invalid_signature` when r or s is 0 or not below
 * n.
 */
template <class Backend = default_backend_t<families::p256>>
[[nodiscard]] boost::system::result<std::size_t> to_der(
    ecdsa_signature const& signature_value, std::span<std::uint8_t> der_output) noexcept {
    secure::timing_guard const timing_scope;
    using engine = detail::p_curve_engine<families::p256, Backend>;
    if (der_output.size() < max_der_size) {
        return error::invalid_input_size;
    }
    std::span<std::uint8_t const, signature_size> const signature_bytes(signature_value.bytes());
    if (!detail::p_curve_signature_in_range<families::p256>(signature_bytes)) {
        return error::invalid_signature;
    }
    std::array<std::uint8_t, max_der_size> der_bytes{};
    std::size_t const der_length = engine::to_der(signature_bytes, der_bytes);
    std::ranges::copy(std::span<std::uint8_t const>(der_bytes).first(der_length),
                      der_output.begin());
    return der_length;
}

/**
 * Decodes a strict DER signature to its raw form: only the encoding `to_der` writes is accepted.
 *
 * @tparam Backend The backend that decodes; by default the family's.
 * @param der_signature The encoding, exactly: nothing may follow it.
 * @return The signature, r then s; `invalid_signature` for anything that is not strict DER (a
 * needless zero byte, a long length where a short one holds it, a negative integer, bytes after
 * it, nothing), and for an r or an s that is 0 or not below n.
 */
template <class Backend = default_backend_t<families::p256>>
[[nodiscard]] boost::system::result<ecdsa_signature> from_der(
    std::span<std::uint8_t const> der_signature) noexcept {
    secure::timing_guard const timing_scope;
    using engine = detail::p_curve_engine<families::p256, Backend>;
    if (der_signature.empty()) {
        return error::invalid_signature;
    }
    std::array<std::uint8_t, signature_size> signature_bytes{};
    if (!engine::from_der(der_signature, signature_bytes) ||
        !detail::p_curve_signature_in_range<families::p256>(signature_bytes)) {
        return error::invalid_signature;
    }
    return detail::signature_access::of<ecdsa_signature>(signature_bytes);
}

/**
 * The low-S form of a signature: s replaced by n - s when s is above (n - 1) / 2, returned
 * unchanged otherwise.
 *
 * Both forms verify with `crypto::verify`; `sign` gives the low form already, so this is for a
 * signature made elsewhere, such as WebCrypto's, whose S may be high. Arithmetic on public bytes,
 * with no backend.
 *
 * @param signature_value The signature.
 * @return The signature with s at most (n - 1) / 2; `invalid_signature` when r or s is 0 or not
 * below n.
 */
[[nodiscard]] inline boost::system::result<ecdsa_signature> normalize_low_s(
    ecdsa_signature const& signature_value) noexcept {
    std::span<std::uint8_t const, signature_size> const signature_bytes(signature_value.bytes());
    if (!detail::p_curve_signature_in_range<families::p256>(signature_bytes)) {
        return error::invalid_signature;
    }
    std::array<std::uint8_t, signature_size> normalized_signature = signature_value.bytes();
    auto const s_value = signature_bytes.last<coordinate_size>();
    if (!detail::p_curve_low_s<families::p256>(s_value)) {
        detail::p_curve_negate_scalar<families::p256>(
            s_value, std::span(normalized_signature).last<coordinate_size>());
    }
    return detail::signature_access::of<ecdsa_signature>(normalized_signature);
}

/**
 * Whether a signature is in its low-S form, as a protocol that requires low S checks what it
 * receives before `crypto::verify`, which accepts both forms; `sign` gives the low form.
 *
 * Arithmetic on public bytes, with no backend; it does not verify the signature.
 *
 * @param signature_value The signature.
 * @return True exactly when 0 < r < n and 0 < s <= (n - 1) / 2.
 */
[[nodiscard]] inline bool is_low_s(ecdsa_signature const& signature_value) noexcept {
    std::span<std::uint8_t const, signature_size> const signature_bytes(signature_value.bytes());
    return detail::p_curve_signature_in_range<families::p256>(signature_bytes) &&
           detail::p_curve_low_s<families::p256>(signature_bytes.last<coordinate_size>());
}

}  // namespace webcpp::crypto::curves::p256

namespace webcpp::crypto {

/**
 * Verifies an ECDSA signature over SHA-256 with a P-256 public key.
 *
 * The key's own `verify` is its member form, with the same work. A high S and a low S are both
 * accepted, as FIPS 186-5 and WebCrypto accept them (WebCrypto's own signatures may be high); a
 * protocol that requires low S checks `curves::p256::is_low_s` too.
 *
 * @tparam Backend The key's backend, which verifies: deduced from the key, or named first, as on
 * every curve, when it is the key's (another backend matches no overload).
 * @tparam Signature `curves::p256::ecdsa_signature`; another type, a signature of another curve
 * or bytes, stops the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included, or `crypto::prehashed<32>`; anything else stops the build.
 * @param signing_scheme `crypto::ecdsa_sha256`.
 * @param signature_value The signature, r then s (IEEE P1363, WebCrypto's form); bytes from a
 * peer are made into one by `curves::p256::ecdsa_signature::from_bytes`, and DER by
 * `curves::p256::from_der`.
 * @param signing_input The signed message, hashed with SHA-256 inside the call; or
 * `crypto::prehashed{digest}`, its 32-byte SHA-256 digest.
 * @param public_key The signer's public key.
 * @return Nothing; `invalid_signature` for an r or an s that is 0 or not below n, refused before
 * the backend, and a signature that does not verify. A digest whose value modulo n is 0 (32 zero
 * bytes, or n itself), which no SHA-256 of a message gives in practice, is refused too: BearSSL's
 * verification refuses a zero multiplier.
 */
template <class Backend, class Signature, class Input>
[[nodiscard]] boost::system::result<void> verify(
    [[maybe_unused]] ecdsa_sha256_t signing_scheme, Signature const& signature_value,
    Input const& signing_input,
    curves::p256::basic_public_key<Backend> const& public_key) noexcept {
    secure::timing_guard const timing_scope;
    static_assert(!detail::asynchronous_backend_v<Backend>,
                  "webcpp::crypto: verify on this backend completes asynchronously: call "
                  "async_verify.");
    if constexpr (!detail::asynchronous_backend_v<Backend>) {
        return detail::p256_verify<Backend>(
            detail::checked_signature_bytes<curves::p256::ecdsa_signature, ecdsa_sha256_t>(
                signature_value),
            signing_input, detail::p_curve_access::point(public_key));
    } else {
        // Never compiled into a program: the assertion above stopped the build.
        return error::invalid_signature;
    }
}

}  // namespace webcpp::crypto

namespace webcpp::crypto::detail {

/**
 * A P-256 key pair signs with ECDSA over SHA-256.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
inline constexpr bool signs_with_v<curves::p256::basic_keypair<Backend>, ecdsa_sha256_t> = true;

/**
 * A P-256 public key verifies ECDSA over SHA-256.
 *
 * @tparam Backend The public key's backend.
 */
template <class Backend>
inline constexpr bool verifies_with_v<curves::p256::basic_public_key<Backend>, ecdsa_sha256_t> =
    true;

/**
 * A P-256 key pair's signature under ECDSA over SHA-256, `curves::p256::ecdsa_signature`.
 *
 * @tparam Backend The key's backend.
 */
template <class Backend>
struct signature_of<curves::p256::basic_keypair<Backend>, ecdsa_sha256_t> {
    /** The signature type. */
    using type = curves::p256::ecdsa_signature;
};

/**
 * A P-256 public key's signature under ECDSA over SHA-256, `curves::p256::ecdsa_signature`.
 *
 * @tparam Backend The key's backend.
 */
template <class Backend>
struct signature_of<curves::p256::basic_public_key<Backend>, ecdsa_sha256_t> {
    /** The signature type. */
    using type = curves::p256::ecdsa_signature;
};

/**
 * A P-256 key pair's backend.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
struct key_backend<curves::p256::basic_keypair<Backend>> {
    /** The backend. */
    using type = Backend;
};

/**
 * A P-256 public key's backend.
 *
 * @tparam Backend The public key's backend.
 */
template <class Backend>
struct key_backend<curves::p256::basic_public_key<Backend>> {
    /** The backend. */
    using type = Backend;
};

/**
 * `crypto::verify` of ECDSA over SHA-256 against a P-256 public key is P-256's, so that the
 * catch-all steps aside.
 *
 * @tparam Backend The public key's backend.
 */
template <class Backend>
inline constexpr bool has_verifier_v<ecdsa_sha256_t, curves::p256::basic_public_key<Backend>> =
    true;

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
    [[nodiscard]] static boost::system::result<void> import_secret(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static bool valid_point(Arguments&&... /*arguments*/) noexcept {
        return false;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> sign(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> ecdh_x(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static bool verify(Arguments&&... /*arguments*/) noexcept {
        return false;
    }

    /** Never called; fails closed: nothing written. */
    template <class... Arguments>
    [[nodiscard]] static std::size_t to_der(Arguments&&... /*arguments*/) noexcept {
        return 0;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static bool from_der(Arguments&&... /*arguments*/) noexcept {
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

// The key pair concepts (design D4), on the family's default backend: it signs and agrees.
static_assert(
    ::webcpp::crypto::keypair<
        ::webcpp::crypto::curves::p256::basic_keypair<::webcpp::crypto::backends::bearssl>>,
    "webcpp::crypto: P-256's key pair meets crypto::keypair.");
static_assert(
    ::webcpp::crypto::signing_keypair<
        ::webcpp::crypto::curves::p256::basic_keypair<::webcpp::crypto::backends::bearssl>>,
    "webcpp::crypto: P-256's key pair meets crypto::signing_keypair.");
static_assert(
    ::webcpp::crypto::agreement_keypair<
        ::webcpp::crypto::curves::p256::basic_keypair<::webcpp::crypto::backends::bearssl>>,
    "webcpp::crypto: P-256's key pair meets crypto::agreement_keypair.");
#endif

#endif  // WEBCPP_CRYPTO_CURVES_P256_HPP
