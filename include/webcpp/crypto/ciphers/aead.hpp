// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `aead<Family, Backend>`, one-shot authenticated encryption in place, and the families it
 takes: ChaCha20-Poly1305, its original form and XChaCha20-Poly1305, and libsodium's
 `crypto_secretbox`, XSalsa20-Poly1305 and XChaCha20-Poly1305 without additional data.

 @see "ChaCha20-Poly1305" and "Secret boxes", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_AEAD_HPP
#define WEBCPP_CRYPTO_CIPHERS_AEAD_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/limits.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto::families {

/** RFC 8439's ChaCha20-Poly1305: a 32-byte key, a 12-byte nonce, a 16-byte tag. */
struct chacha20_poly1305 {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly (RFC 8439 section 2.8). */
    static constexpr std::size_t iv_size = 12;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^38 - 64 bytes: ChaCha20's 32-bit block counter (section 2.8). */
    static constexpr std::uint64_t max_message_size = (std::uint64_t{1} << 38U) - 64;
    /** The longest additional data, 2^64 - 1 bytes (section 2.8). */
    static constexpr std::uint64_t max_additional_data_size = ~std::uint64_t{0};
};

/**
 * The original ChaCha20-Poly1305, an 8-byte nonce and a 64-bit block counter, as libsodium's
 * `crypto_aead_chacha20poly1305` has it.
 */
struct chacha20_poly1305_original {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t iv_size = 8;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^64 - 17 bytes. */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;
    /** The longest additional data, 2^64 - 1 bytes. */
    static constexpr std::uint64_t max_additional_data_size = ~std::uint64_t{0};
};

/** XChaCha20-Poly1305, a 24-byte nonce safe to draw at random. */
struct xchacha20_poly1305 {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t iv_size = 24;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^64 - 17 bytes. */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;
    /** The longest additional data, 2^64 - 1 bytes. */
    static constexpr std::uint64_t max_additional_data_size = ~std::uint64_t{0};
};

/**
 * NaCl's and libsodium's `crypto_secretbox`, XSalsa20-Poly1305: a 32-byte key, a 24-byte nonce
 * safe to draw at random, a 16-byte tag, and no additional data.
 */
struct secretbox_xsalsa20poly1305 {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t iv_size = 24;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /**
     * The longest message, 2^64 - 17 bytes: libsodium's `crypto_secretbox_MESSAGEBYTES_MAX` on a
     * 64-bit target.
     *
     * On a 32-bit target, wasm32 among them, libsodium's is 2^32 - 17 bytes, more than a
     * message there can be, since the 4 GiB of memory also hold the program.
     */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;
    /** No additional data: `aead` refuses a non-empty one with `invalid_input_size`. */
    static constexpr std::uint64_t max_additional_data_size = 0;
};

/**
 * libsodium's `crypto_secretbox_xchacha20poly1305`: `crypto_secretbox` with XChaCha20 in place
 * of XSalsa20, a 24-byte nonce safe to draw at random, and no additional data.
 */
struct secretbox_xchacha20poly1305 {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t iv_size = 24;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^64 - 17 bytes. */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;
    /** No additional data: `aead` refuses a non-empty one with `invalid_input_size`. */
    static constexpr std::uint64_t max_additional_data_size = 0;
};

}  // namespace webcpp::crypto::families

namespace webcpp::crypto::detail {

/**
 * What a `ciphers::aead` stores on a backend whose header does not specialise it: nothing,
 * since its engine refuses the backend where the family is called.
 */
template <class Family, class Backend>
struct aead_state {};

/** Whether `Family` is one of the AEAD families `ciphers::aead` takes. */
template <class Family>
inline constexpr bool aead_family = false;

/** ChaCha20-Poly1305 is an AEAD family. */
template <>
inline constexpr bool aead_family<families::chacha20_poly1305> = true;

/** The original ChaCha20-Poly1305 is an AEAD family. */
template <>
inline constexpr bool aead_family<families::chacha20_poly1305_original> = true;

/** XChaCha20-Poly1305 is an AEAD family. */
template <>
inline constexpr bool aead_family<families::xchacha20_poly1305> = true;

/** `crypto_secretbox`, XSalsa20-Poly1305, is an AEAD family without additional data. */
template <>
inline constexpr bool aead_family<families::secretbox_xsalsa20poly1305> = true;

/** `crypto_secretbox_xchacha20poly1305` is an AEAD family without additional data. */
template <>
inline constexpr bool aead_family<families::secretbox_xchacha20poly1305> = true;

/**
 * The sizes and limits `ciphers::aead` reads from its family: the family's own.
 *
 * @tparam Family An AEAD family.
 */
template <class Family, bool = aead_family<Family>>
struct aead_sizes : Family {};

/**
 * The sizes of a type that is no AEAD family, which `ciphers::aead` refuses first: placeholders,
 * so that the compiler adds no error of its own after the refusal.
 */
template <class Family>
struct aead_sizes<Family, false> {
    /** A placeholder. */
    static constexpr std::size_t key_size = 1;
    /** A placeholder. */
    static constexpr std::size_t iv_size = 1;
    /** A placeholder. */
    static constexpr std::size_t tag_size = 1;
    /** A placeholder. */
    static constexpr std::uint64_t max_message_size = 0;
    /** A placeholder. */
    static constexpr std::uint64_t max_additional_data_size = 0;
};

/**
 * The refusal of an AEAD family on a backend whose header does not specialise its engine: each
 * family's below. A type that is no AEAD family has none here: `ciphers::aead` refuses it first.
 */
template <class Family, class Backend>
struct aead_refusal {};

/** ChaCha20-Poly1305's refusal, which names what the program needs (`detail/capabilities.hpp`). */
template <class Backend>
struct aead_refusal<families::chacha20_poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_CHACHA20_POLY1305(Backend);
};

/** The original ChaCha20-Poly1305's refusal (see the first). */
template <class Backend>
struct aead_refusal<families::chacha20_poly1305_original, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_CHACHA20_POLY1305_ORIGINAL(Backend);
};

/** XChaCha20-Poly1305's refusal (see the first). */
template <class Backend>
struct aead_refusal<families::xchacha20_poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_XCHACHA20_POLY1305(Backend);
};

/** XSalsa20-Poly1305's secret box's refusal (see the first). */
template <class Backend>
struct aead_refusal<families::secretbox_xsalsa20poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECRETBOX_XSALSA20POLY1305(Backend);
};

/** XChaCha20-Poly1305's secret box's refusal (see the first). */
template <class Backend>
struct aead_refusal<families::secretbox_xchacha20poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECRETBOX_XCHACHA20POLY1305(Backend);
};

/**
 * An AEAD's engine on a backend whose header does not specialise it: the family's refusal.
 * Its functions are never called: the refusal stops the build where the class is
 * instantiated, and they keep the compiler from adding errors of their own after it; those
 * that return report `backend_failure`, so that a path the refusal missed fails closed.
 */
template <class Family, class Backend>
struct aead_engine : aead_refusal<Family, Backend> {
    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> init(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> seal(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> open(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void move(Arguments&&... /*arguments*/) noexcept {}

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::ciphers {

/**
 * An AEAD of the family `Family` on `Backend`, one shot: authenticated encryption in place,
 * the tag apart.
 *
 * An object holds a key: it is used by one thread at a time. A nonce (the IV) is never
 * repeated under one key: two messages under one key and one nonce reveal the XOR of their
 * plaintexts and let an attacker forge tags. Drawn at random, ChaCha20-Poly1305's 12-byte
 * nonce lets a key seal at most 2^32 messages, and the original's 8 bytes are too few: a
 * counter numbers them. XChaCha20-Poly1305's 24-byte nonce, and the secret boxes', are safe
 * to draw at random.
 *
 * @tparam Family `families::chacha20_poly1305`, `families::chacha20_poly1305_original`,
 * `families::xchacha20_poly1305`, or the secret boxes' `families::secretbox_xsalsa20poly1305`
 * and `families::secretbox_xchacha20poly1305`, which take no additional data.
 * @tparam Backend The backend; `ciphers::chacha20_poly1305<>`, its two siblings and
 * `ciphers::secretbox<>` and its twin name the family's default.
 */
template <class Family, class Backend>
class aead {
    // The first error a program that names another type sees, and its only one.
    static_assert(detail::aead_family<Family>,
                  "webcpp::crypto: ciphers::aead takes an AEAD family: "
                  "families::chacha20_poly1305, families::chacha20_poly1305_original, "
                  "families::xchacha20_poly1305, families::secretbox_xsalsa20poly1305 or "
                  "families::secretbox_xchacha20poly1305.");

    using sizes = detail::aead_sizes<Family>;
    using state_type = detail::aead_state<Family, Backend>;
    using engine = detail::aead_engine<Family, Backend>;

public:
    /** The backend. */
    using backend_type = Backend;
    /** The family of the capability table, which `supports_v` reads. */
    using family_type = Family;
    /** The algorithm of the capability table: the family's own tag, its one algorithm. */
    using name_type = Family;
    /** The tag, Boost.Hash2's digest of `tag_size` bytes. */
    using result_type = boost::hash2::digest<sizes::tag_size>;
    /** The key's size. */
    static constexpr std::size_t key_size = sizes::key_size;
    /** The nonce's size, exactly. */
    static constexpr std::size_t iv_size = sizes::iv_size;
    /** The tag's size. */
    static constexpr std::size_t tag_size = sizes::tag_size;
    /** The longest message. */
    static constexpr std::uint64_t max_message_size = sizes::max_message_size;
    /** The longest additional data; 0 for a family that takes none. */
    static constexpr std::uint64_t max_additional_data_size = sizes::max_additional_data_size;

    /**
     * Makes an object under a key.
     *
     * @param key_bytes `key_size` bytes.
     * @return The object; `invalid_key_size`; `backend_failure` when the backend cannot start.
     */
    [[nodiscard]] static boost::system::result<aead> make(
        std::span<std::uint8_t const> key_bytes) noexcept {
        if (key_bytes.size() != key_size) {
            return error::invalid_key_size;
        }
        aead made_object;
        auto const key_result = engine::init(made_object.state_, key_bytes);
        if (!key_result) {
            return key_result.error();
        }
        made_object.keyed_ = true;
        return made_object;
    }

    /**
     * Moves the key; the source is wiped and empty.
     *
     * Moving an empty object gives an empty one.
     *
     * @param moved_source The source, empty afterwards.
     */
    aead(aead&& moved_source) noexcept : keyed_(std::exchange(moved_source.keyed_, false)) {
        if (keyed_) {
            engine::move(state_, moved_source.state_);
        }
    }

    /**
     * Moves the key over this one, which is wiped first; an empty source gives an empty object.
     *
     * @param moved_source The source, empty afterwards.
     * @return This object.
     */
    aead& operator=(aead&& moved_source) noexcept {
        if (this != &moved_source) {
            engine::reset(state_);
            keyed_ = std::exchange(moved_source.keyed_, false);
            if (keyed_) {
                engine::move(state_, moved_source.state_);
            }
        }
        return *this;
    }

    /** Not copyable: a key has one owner, which wipes it. */
    aead(aead const&) = delete;
    /** Not copyable: a key has one owner, which wipes it. */
    aead& operator=(aead const&) = delete;

    /** Wipes the key. */
    ~aead() { engine::reset(state_); }

    /**
     * Seals a message in place: `data_bytes` holds the plaintext before and the ciphertext
     * after.
     *
     * The nonce is read before the first byte of `data_bytes` is written, so it may lie in
     * `data_bytes`. The additional data may touch `data_bytes`, as a wire format that puts it
     * just before the message does, but not overlap it: BearSSL's ChaCha20-Poly1305 reads it
     * after it encrypts, in one call over the whole message, so an overlap would authenticate
     * other bytes than the caller's additional data; the backends would give different tags,
     * and an open with the original additional data would fail.
     *
     * @param iv_bytes The nonce, `iv_size` bytes, never repeated under this key.
     * @param additional_data_bytes Authenticated, not encrypted; empty for a family that takes
     * none (`max_additional_data_size` 0).
     * @param data_bytes The message.
     * @return The tag; `invalid_state` moved from; `invalid_iv_size`; `invalid_input_size` for
     * additional data given to a family that takes none; `message_too_long`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<result_type> seal(
        std::span<std::uint8_t const> iv_bytes, std::span<std::uint8_t const> additional_data_bytes,
        std::span<std::uint8_t> data_bytes) noexcept {
        auto const guard_result =
            guard_message(iv_bytes, additional_data_bytes, data_bytes.size(), tag_size);
        if (!guard_result) {
            return guard_result.error();
        }
        result_type tag_bytes{};
        auto const seal_result =
            engine::seal(state_, iv_bytes, additional_data_bytes, data_bytes, tag_bytes);
        if (!seal_result) {
            return seal_result.error();
        }
        return tag_bytes;
    }

    /**
     * Opens a message in place: `data_bytes` holds the ciphertext before and the plaintext
     * after.
     *
     * When the tag does not match, or the backend fails, `data_bytes` is zeroed; a guard's
     * refusal leaves it untouched.
     *
     * @param iv_bytes The nonce of the seal.
     * @param additional_data_bytes The additional data of the seal.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, `tag_size` bytes, which may lie anywhere, `data_bytes`
     * included.
     * @return Nothing; `invalid_state` moved from; `invalid_iv_size`; `invalid_tag_size`;
     * `invalid_input_size` for additional data given to a family that takes none;
     * `message_too_long`; `authentication_failed`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> open(
        std::span<std::uint8_t const> iv_bytes, std::span<std::uint8_t const> additional_data_bytes,
        std::span<std::uint8_t> data_bytes, std::span<std::uint8_t const> tag_bytes) noexcept {
        auto const guard_result =
            guard_message(iv_bytes, additional_data_bytes, data_bytes.size(), tag_bytes.size());
        if (!guard_result) {
            return guard_result.error();
        }
        // The tag may lie in data, which decryption overwrites: a copy is checked.
        std::array<std::uint8_t, tag_size> expected_tag{};
        std::ranges::copy(tag_bytes, expected_tag.begin());
        auto const open_result =
            engine::open(state_, iv_bytes, additional_data_bytes, data_bytes, expected_tag);
        if (!open_result) {
            detail::wipe(data_bytes.data(), data_bytes.size());
            return open_result.error();
        }
        return {};
    }

private:
    aead() noexcept = default;

    // Every guard of a message, in the documented order: the state, the nonce, the tag
    // (open's; seal passes tag_size), additional data given to a family that takes none, the
    // lengths. None reads a byte of the spans.
    [[nodiscard]] boost::system::result<void> guard_message(
        std::span<std::uint8_t const> iv_bytes, std::span<std::uint8_t const> additional_data_bytes,
        std::size_t byte_count, std::size_t tag_bytes) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (iv_bytes.size() != iv_size) {
            return error::invalid_iv_size;
        }
        if (tag_bytes != tag_size) {
            return error::invalid_tag_size;
        }
        if constexpr (max_additional_data_size == 0) {
            if (!additional_data_bytes.empty()) {
                return error::invalid_input_size;
            }
        }
        if (detail::exceeds(byte_count, max_message_size) ||
            detail::exceeds(additional_data_bytes.size(), max_additional_data_size)) {
            return error::message_too_long;
        }
        return {};
    }

    state_type state_{};
    bool keyed_ = false;
};

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_AEAD_HPP
