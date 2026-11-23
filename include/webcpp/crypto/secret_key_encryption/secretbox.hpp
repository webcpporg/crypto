// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `basic_secretbox`, NaCl's and libsodium's secret boxes: authenticated encryption in place under
 one 32-byte key, the tag apart, without associated data, an `authenticated_box`. `secretbox` and
 `secretbox_xchacha20poly1305` name the two families, XSalsa20-Poly1305 and XChaCha20-Poly1305,
 each on its family's default backend unless the type names another: libsodium on every target,
 whose header it includes when the program links it (`default_backend_t`). A program that uses
 them without linking the default stops where it calls them, with the Jamfile line that links
 it.

 The namespace is named by the problem the construction solves, encryption under one secret key,
 parallel to `public_key_encryption::box`, encryption between key pairs (owner decision 13): a
 secret box is no AEAD, since it takes no associated data, so it is not among `ciphers`'
 algorithms, and its free forms are the box forms, `secret_key_encryption::seal` and `open`.

 @see "Secret boxes", in the guide.
*/
#ifndef WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_SECRETBOX_HPP
#define WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_SECRETBOX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/asynchronous.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/limits.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>  // crypto::from_key, which serves its from_key (design R23)
#include <webcpp/crypto/secret_key_encryption/authenticated_box.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto::families {

/**
 * NaCl's and libsodium's `crypto_secretbox`, XSalsa20-Poly1305: a 32-byte key, a 24-byte nonce
 * safe to draw at random, a 16-byte tag, and no associated data.
 */
struct secretbox_xsalsa20poly1305 {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t nonce_size = 24;
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
};

/**
 * libsodium's `crypto_secretbox_xchacha20poly1305`: `crypto_secretbox` with XChaCha20 in place
 * of XSalsa20, a 24-byte nonce safe to draw at random, and no associated data.
 */
struct secretbox_xchacha20poly1305 {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t nonce_size = 24;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^64 - 17 bytes. */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;
};

}  // namespace webcpp::crypto::families

namespace webcpp::crypto::detail {

/**
 * What a `secret_key_encryption::basic_secretbox` stores on a backend whose header does not
 * specialise it: nothing, since its engine refuses the backend where the family is called.
 */
template <class Family, class Backend>
struct secretbox_state {};

/** Whether `Family` is one of the families `secret_key_encryption::basic_secretbox` takes. */
template <class Family>
inline constexpr bool secretbox_family = false;

/** `crypto_secretbox`, XSalsa20-Poly1305, is a secret box family. */
template <>
inline constexpr bool secretbox_family<families::secretbox_xsalsa20poly1305> = true;

/** `crypto_secretbox_xchacha20poly1305` is a secret box family. */
template <>
inline constexpr bool secretbox_family<families::secretbox_xchacha20poly1305> = true;

/**
 * The sizes and limits `secret_key_encryption::basic_secretbox` reads from its family: the
 * family's own.
 *
 * @tparam Family A secret box family.
 */
template <class Family, bool = secretbox_family<Family>>
struct secretbox_sizes : Family {};

/**
 * The sizes of a type that is no secret box family, which `basic_secretbox` refuses first:
 * placeholders, so that the compiler adds no error of its own after the refusal.
 */
template <class Family>
struct secretbox_sizes<Family, false> {
    /** A placeholder. */
    static constexpr std::size_t key_size = 1;
    /** A placeholder. */
    static constexpr std::size_t nonce_size = 1;
    /** A placeholder. */
    static constexpr std::size_t tag_size = 1;
    /** A placeholder. */
    static constexpr std::uint64_t max_message_size = 0;
};

/**
 * The refusal of a secret box family on a backend whose header does not specialise its engine:
 * each family's below. A type that is no secret box family has none here: `basic_secretbox`
 * refuses it first.
 */
template <class Family, class Backend>
struct secretbox_refusal {};

/** XSalsa20-Poly1305's secret box's refusal, which names what the program needs. */
template <class Backend>
struct secretbox_refusal<families::secretbox_xsalsa20poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECRETBOX_XSALSA20POLY1305(Backend);
};

/** XChaCha20-Poly1305's secret box's refusal (see the first). */
template <class Backend>
struct secretbox_refusal<families::secretbox_xchacha20poly1305, Backend> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECRETBOX_XCHACHA20POLY1305(Backend);
};

/**
 * A secret box's engine on a backend whose header does not specialise it: the family's refusal
 * (`detail/capabilities.hpp`). Its functions are never called: the refusal stops the build where
 * the class is instantiated, and they keep the compiler from adding errors of their own after
 * it; those that return report `backend_failure`, so that a path the refusal missed fails
 * closed.
 */
template <class Family, class Backend>
struct secretbox_engine : secretbox_refusal<Family, Backend> {
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

namespace webcpp::crypto::secret_key_encryption {

/**
 * A secret box of the family `Family` on `Backend`: authenticated encryption in place under one
 * key, the tag apart, without associated data.
 *
 * An object holds a key: it is used by one thread at a time, moved and not copied, and wiped
 * when moved from and destroyed. A nonce is never repeated under one key: two messages under
 * one key and one nonce reveal the XOR of their plaintexts and let an attacker forge tags. Its
 * 24 bytes are safe to draw at random for every message.
 *
 * @tparam Family `families::secretbox_xsalsa20poly1305`, NaCl's `crypto_secretbox`, or
 * `families::secretbox_xchacha20poly1305`, libsodium's `crypto_secretbox_xchacha20poly1305`.
 * @tparam Backend The backend; `secretbox<>` and `secretbox_xchacha20poly1305<>` name the
 * family's default.
 */
template <class Family, class Backend>
class basic_secretbox {
    // The first error a program that names another type sees, and its only one.
    static_assert(detail::secretbox_family<Family>,
                  "webcpp::crypto: secret_key_encryption::basic_secretbox takes a secret box "
                  "family: families::secretbox_xsalsa20poly1305 or "
                  "families::secretbox_xchacha20poly1305.");

    using sizes = detail::secretbox_sizes<Family>;
    using state_type = detail::secretbox_state<Family, Backend>;
    using engine = detail::secretbox_engine<Family, Backend>;

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
    static constexpr std::size_t nonce_size = sizes::nonce_size;
    /** The tag's size. */
    static constexpr std::size_t tag_size = sizes::tag_size;
    /** The longest message. */
    static constexpr std::uint64_t max_message_size = sizes::max_message_size;

    /**
     * Makes a box under a key.
     *
     * @param key_bytes `key_size` bytes.
     * @return The box; `invalid_key_size`; `backend_failure` when the backend cannot start.
     */
    [[nodiscard]] static boost::system::result<basic_secretbox> from_key(
        std::span<std::uint8_t const> key_bytes) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(!detail::asynchronous_backend_v<Backend>,
                      "webcpp::crypto: from_key on this backend completes asynchronously: call "
                      "async_from_key.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            if (key_bytes.size() != key_size) {
                return error::invalid_key_size;
            }
            basic_secretbox made_object;
            auto const key_result = engine::init(made_object.state_, key_bytes);
            if (!key_result) {
                return key_result.error();
            }
            made_object.keyed_ = true;
            return made_object;
        }
    }

    /**
     * Moves the key; the source is wiped and empty.
     *
     * Moving an empty box gives an empty one.
     *
     * @param moved_source The source, empty afterwards.
     */
    basic_secretbox(basic_secretbox&& moved_source) noexcept
        : keyed_(std::exchange(moved_source.keyed_, false)) {
        if (keyed_) {
            engine::move(state_, moved_source.state_);
        }
    }

    /**
     * Moves the key over this one, which is wiped first; an empty source gives an empty box.
     *
     * @param moved_source The source, empty afterwards.
     * @return This box.
     */
    basic_secretbox& operator=(basic_secretbox&& moved_source) noexcept {
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
    basic_secretbox(basic_secretbox const&) = delete;
    /** Not copyable: a key has one owner, which wipes it. */
    basic_secretbox& operator=(basic_secretbox const&) = delete;

    /** Wipes the key. */
    ~basic_secretbox() { engine::reset(state_); }

    /**
     * Seals a message in place: `data_bytes` holds the plaintext before and the ciphertext
     * after.
     *
     * The nonce is read before the first byte of `data_bytes` is written, so it may lie in
     * `data_bytes`.
     *
     * When the backend fails, `data_bytes` is zeroed, as a failed open's is: neither the
     * plaintext nor bytes that look sealed are left; a guard's refusal leaves it untouched.
     *
     * @param nonce_bytes The nonce, `nonce_size` bytes, never repeated under this key.
     * @param data_bytes The message.
     * @return The tag; `invalid_state` moved from; `invalid_nonce_size`; `message_too_long`;
     * `backend_failure`.
     */
    [[nodiscard]] boost::system::result<result_type> seal(
        std::span<std::uint8_t const> nonce_bytes, std::span<std::uint8_t> data_bytes) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(
            !detail::asynchronous_backend_v<Backend>,
            "webcpp::crypto: seal on this backend completes asynchronously: call async_seal.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            auto const guard_result = guard_message(nonce_bytes, data_bytes.size(), tag_size);
            if (!guard_result) {
                return guard_result.error();
            }
            result_type tag_bytes{};
            auto const seal_result =
                engine::seal(state_, nonce_bytes.first<nonce_size>(), data_bytes, tag_bytes);
            if (!seal_result) {
                detail::wipe(data_bytes.data(), data_bytes.size());
                return seal_result.error();
            }
            return tag_bytes;
        }
    }

    /**
     * Opens a message in place: `data_bytes` holds the ciphertext before and the plaintext
     * after.
     *
     * When the tag does not match, or the backend fails, `data_bytes` is zeroed; a guard's
     * refusal leaves it untouched.
     *
     * @param nonce_bytes The nonce of the seal, which may lie in `data_bytes`.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, `tag_size` bytes, which may lie anywhere, `data_bytes`
     * included.
     * @return Nothing; `invalid_state` moved from; `invalid_nonce_size`; `invalid_tag_size`;
     * `message_too_long`; `authentication_failed`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> open(
        std::span<std::uint8_t const> nonce_bytes, std::span<std::uint8_t> data_bytes,
        std::span<std::uint8_t const> tag_bytes) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(
            !detail::asynchronous_backend_v<Backend>,
            "webcpp::crypto: open on this backend completes asynchronously: call async_open.");
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            auto const guard_result =
                guard_message(nonce_bytes, data_bytes.size(), tag_bytes.size());
            if (!guard_result) {
                return guard_result.error();
            }
            // The tag may lie in data, which decryption overwrites: a copy is checked.
            std::array<std::uint8_t, tag_size> expected_tag{};
            std::ranges::copy(tag_bytes, expected_tag.begin());
            auto const open_result =
                engine::open(state_, nonce_bytes.first<nonce_size>(), data_bytes, expected_tag);
            if (!open_result) {
                detail::wipe(data_bytes.data(), data_bytes.size());
                return open_result.error();
            }
            return {};
        }
    }

private:
    basic_secretbox() noexcept = default;

    // Every guard of a message, in the documented order: the state, the nonce, the tag (open's;
    // seal passes tag_size), the length. None reads a byte of the spans.
    [[nodiscard]] boost::system::result<void> guard_message(
        std::span<std::uint8_t const> nonce_bytes, std::size_t byte_count,
        std::size_t tag_bytes) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (nonce_bytes.size() != nonce_size) {
            return error::invalid_nonce_size;
        }
        if (tag_bytes != tag_size) {
            return error::invalid_tag_size;
        }
        if (detail::exceeds(byte_count, max_message_size)) {
            return error::message_too_long;
        }
        return {};
    }

    state_type state_{};
    bool keyed_ = false;
};

/**
 * NaCl's and libsodium's `crypto_secretbox`, XSalsa20-Poly1305: a 32-byte key, a 24-byte nonce
 * safe to draw at random, a 16-byte tag, and no associated data.
 *
 * @tparam Backend The backend; the default is the family's.
 */
template <class Backend = default_backend_t<families::secretbox_xsalsa20poly1305>>
using secretbox = basic_secretbox<families::secretbox_xsalsa20poly1305, Backend>;

/**
 * libsodium's `crypto_secretbox_xchacha20poly1305`: the secret box with XChaCha20 in place of
 * XSalsa20, of the same sizes and without associated data.
 *
 * @tparam Backend The backend; the default is the family's.
 */
template <class Backend = default_backend_t<families::secretbox_xchacha20poly1305>>
using secretbox_xchacha20poly1305 = basic_secretbox<families::secretbox_xchacha20poly1305, Backend>;

// Each secret box is an authenticated_box, and no AEAD (design D5's table).
static_assert(authenticated_box<secretbox<detail::concept_check_backend>>);
static_assert(authenticated_box<secretbox_xchacha20poly1305<detail::concept_check_backend>>);
static_assert(!aead::cipher<secretbox<detail::concept_check_backend>>);

}  // namespace webcpp::crypto::secret_key_encryption

// The default backend's engines, when the program links it (design D32): libsodium on every
// target. Its header specialises them for this header, wherever it was first included.
#if (defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SECRETBOX_XSALSA20POLY1305_SODIUM) ||   \
     defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SECRETBOX_XCHACHA20POLY1305_SODIUM)) && \
    defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_SECRETBOX_HPP
