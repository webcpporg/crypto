// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `basic_chacha20_poly1305<Family, Backend>`, one-shot authenticated encryption in place with
 associated data, and the families it takes: ChaCha20-Poly1305, its original form and
 XChaCha20-Poly1305. Each is a `secret_key_encryption::aead::cipher` (design D5), whose header,
 which this one includes, holds the free synchronous forms of every AEAD's members, AES-GCM's
 included (design D9, D11),
 `secret_key_encryption::aead::seal(cipher, nonce, associated_data, data)` and
 `secret_key_encryption::aead::open(cipher, nonce, associated_data, data, tag)`. The secret boxes,
 which take no associated data, are `secret_key_encryption::basic_secretbox`.

 @see "ChaCha20-Poly1305" and "The AEAD contract", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_AEAD_HPP
#define WEBCPP_CRYPTO_CIPHERS_AEAD_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/asynchronous.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/limits.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>  // crypto::from_key, which serves its from_key (design R23)
#include <webcpp/crypto/secret_key_encryption/aead.hpp>  // its free seal and open (design D11)
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/timing_guard.hpp>

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
    static constexpr std::size_t nonce_size = 12;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^38 - 64 bytes: ChaCha20's 32-bit block counter (section 2.8). */
    static constexpr std::uint64_t max_message_size = (std::uint64_t{1} << 38U) - 64;
    /** The longest associated data, 2^64 - 1 bytes (section 2.8). */
    static constexpr std::uint64_t max_associated_data_size = ~std::uint64_t{0};
};

/**
 * The original ChaCha20-Poly1305, an 8-byte nonce and a 64-bit block counter, as libsodium's
 * `crypto_aead_chacha20poly1305` has it.
 */
struct chacha20_poly1305_original {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t nonce_size = 8;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^64 - 17 bytes. */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;
    /** The longest associated data, 2^64 - 1 bytes. */
    static constexpr std::uint64_t max_associated_data_size = ~std::uint64_t{0};
};

/** XChaCha20-Poly1305, a 24-byte nonce safe to draw at random. */
struct xchacha20_poly1305 {
    /** The key's size. */
    static constexpr std::size_t key_size = 32;
    /** The nonce's size, exactly. */
    static constexpr std::size_t nonce_size = 24;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The longest message, 2^64 - 17 bytes. */
    static constexpr std::uint64_t max_message_size = ~std::uint64_t{0} - 16;
    /** The longest associated data, 2^64 - 1 bytes. */
    static constexpr std::uint64_t max_associated_data_size = ~std::uint64_t{0};
};

}  // namespace webcpp::crypto::families

namespace webcpp::crypto::detail {

/**
 * What a `ciphers::basic_chacha20_poly1305` stores on a backend whose header does not specialise
 * it: nothing, since its engine refuses the backend where the family is called.
 */
template <class Family, class Backend>
struct aead_state {};

/** Whether `Family` is one of the AEAD families `ciphers::basic_chacha20_poly1305` takes. */
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

/**
 * The sizes and limits `ciphers::basic_chacha20_poly1305` reads from its family: the family's own.
 *
 * @tparam Family An AEAD family.
 */
template <class Family, bool = aead_family<Family>>
struct aead_sizes : Family {};

/**
 * The sizes of a type that is no AEAD family, which `ciphers::basic_chacha20_poly1305` refuses
 * first: placeholders, so that the compiler adds no error of its own after the refusal.
 */
template <class Family>
struct aead_sizes<Family, false> {
    /** A placeholder. */
    static constexpr std::size_t key_size = 1;
    /** A placeholder. */
    static constexpr std::size_t nonce_size = 1;
    /** A placeholder. */
    static constexpr std::size_t tag_size = 1;
    /** A placeholder. */
    static constexpr std::uint64_t max_message_size = 0;
    /** A placeholder. */
    static constexpr std::uint64_t max_associated_data_size = 0;
};

/**
 * The refusal of an AEAD family on a backend whose header does not specialise its engine: each
 * family's below. A type that is no AEAD family has none here: `ciphers::basic_chacha20_poly1305`
 * refuses it first.
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
 * An AEAD of the family `Family` on `Backend`, one shot: authenticated encryption in place with
 * associated data, the tag apart.
 *
 * An object holds a key: it is used by one thread at a time. A nonce is never
 * repeated under one key: two messages under one key and one nonce reveal the XOR of their
 * plaintexts and let an attacker forge tags. Drawn at random, ChaCha20-Poly1305's 12-byte
 * nonce lets a key seal at most 2^32 messages, and the original's 8 bytes are too few: a
 * counter numbers them. XChaCha20-Poly1305's 24-byte nonce is safe to draw at random.
 *
 * @tparam Family `families::chacha20_poly1305`, `families::chacha20_poly1305_original` or
 * `families::xchacha20_poly1305`.
 * @tparam Backend The backend; `ciphers::chacha20_poly1305<>` and its two siblings name the
 * family's default.
 */
template <class Family, class Backend>
class basic_chacha20_poly1305 {
    // The first error a program that names another type sees, and its only one.
    static_assert(detail::aead_family<Family>,
                  "webcpp::crypto: ciphers::basic_chacha20_poly1305 takes an AEAD family: "
                  "families::chacha20_poly1305, families::chacha20_poly1305_original or "
                  "families::xchacha20_poly1305.");

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
    static constexpr std::size_t nonce_size = sizes::nonce_size;
    /** The tag's size. */
    static constexpr std::size_t tag_size = sizes::tag_size;
    /** The longest message. */
    static constexpr std::uint64_t max_message_size = sizes::max_message_size;
    /** The longest associated data. */
    static constexpr std::uint64_t max_associated_data_size = sizes::max_associated_data_size;

    /**
     * Makes an object under a key.
     *
     * @param key_bytes `key_size` bytes.
     * @return The object; `invalid_key_size`; `backend_failure` when the backend cannot start.
     */
    [[nodiscard]] static boost::system::result<basic_chacha20_poly1305> from_key(
        std::span<std::uint8_t const> key_bytes) noexcept {
        secure::timing_guard const timing_scope;
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // WebCrypto has no such construction: the refusal names a native backend (design D6).
            detail::refuse_aead_on_asynchronous_backend<Backend>();
            return error::backend_failure;
        } else {
            if (key_bytes.size() != key_size) {
                return error::invalid_key_size;
            }
            basic_chacha20_poly1305 made_object;
            auto const key_result = engine::init(made_object.state_, key_bytes);
            if (!key_result) {
                return key_result.error();
            }
            made_object.keyed_ = true;
            return made_object;
        }
    }

    /**
     * Makes an object under a key, asynchronously: `from_key` run when the operation is initiated,
     * its result posted to `completion_executor`; the member form of
     * `crypto::async_from_key<basic_chacha20_poly1305>(executor, key_bytes, token)`, which calls
     * it.
     *
     * On a native backend only: WebCrypto has no ChaCha20-Poly1305, and on a backend that
     * completes by itself this call stops the build, as `from_key`, `seal`, `open` and the other
     * asynchronous forms do (design D6).
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param key_bytes `key_size` bytes, the caller's until the completion.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, basic_chacha20_poly1305)`; on an error the object is empty,
     * and every member refuses with `invalid_state` (`invalid_key_size`, `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    static auto async_from_key(Executor const& completion_executor,
                               std::span<std::uint8_t const> key_bytes,
                               CompletionToken&& completion_token);

    /**
     * Moves the key; the source is wiped and empty.
     *
     * Moving an empty object gives an empty one.
     *
     * @param moved_source The source, empty afterwards.
     */
    basic_chacha20_poly1305(basic_chacha20_poly1305&& moved_source) noexcept
        : keyed_(std::exchange(moved_source.keyed_, false)) {
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
    basic_chacha20_poly1305& operator=(basic_chacha20_poly1305&& moved_source) noexcept {
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
    basic_chacha20_poly1305(basic_chacha20_poly1305 const&) = delete;
    /** Not copyable: a key has one owner, which wipes it. */
    basic_chacha20_poly1305& operator=(basic_chacha20_poly1305 const&) = delete;

    /** Wipes the key. */
    ~basic_chacha20_poly1305() { engine::reset(state_); }

    /**
     * Seals a message in place: `data_bytes` holds the plaintext before and the ciphertext
     * after.
     *
     * The nonce is read before the first byte of `data_bytes` is written, so it may lie in
     * `data_bytes`. The associated data may touch `data_bytes`, as a wire format that puts it
     * just before the message does, but not overlap it: BearSSL's ChaCha20-Poly1305 reads it
     * after it encrypts, in one call over the whole message, so an overlap would authenticate
     * other bytes than the caller's associated data; the backends would give different tags,
     * and an open with the original associated data would fail.
     *
     * When the backend fails, `data_bytes` is zeroed, as a failed open's is: a backend may fail
     * after it began to encrypt, and neither the plaintext nor bytes that look sealed are left;
     * a guard's refusal leaves it untouched.
     *
     * @param nonce_bytes The nonce, `nonce_size` bytes, never repeated under this key.
     * @param associated_data_bytes Authenticated, not encrypted.
     * @param data_bytes The message.
     * @return The tag; `invalid_state` moved from; `invalid_nonce_size`; `message_too_long`;
     * `backend_failure`.
     */
    [[nodiscard]] boost::system::result<result_type> seal(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes,
        std::span<std::uint8_t> data_bytes) noexcept {
        secure::timing_guard const timing_scope;
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // WebCrypto has no such construction: the refusal names a native backend (design D6).
            detail::refuse_aead_on_asynchronous_backend<Backend>();
            return error::backend_failure;
        } else {
            auto const guard_result =
                guard_message(nonce_bytes, associated_data_bytes, data_bytes.size(), tag_size);
            if (!guard_result) {
                return guard_result.error();
            }
            result_type tag_bytes{};
            auto const seal_result =
                engine::seal(state_, nonce_bytes, associated_data_bytes, data_bytes, tag_bytes);
            if (!seal_result) {
                secure::erase_secret(data_bytes);
                return seal_result.error();
            }
            return tag_bytes;
        }
    }

    /**
     * Seals a message in place, asynchronously: `seal` run when the operation is initiated, its
     * result posted to `completion_executor`; the member form of
     * `secret_key_encryption::aead::async_seal(executor, cipher, nonce_bytes,
     * associated_data_bytes, data_bytes, token)`, which calls it.
     *
     * The object and the spans are the caller's until the completion; `data_bytes` holds the
     * ciphertext at the completion. On a native backend only: on a backend that completes by
     * itself the call stops the build (design D6).
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile.
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param nonce_bytes The nonce, `nonce_size` bytes, never repeated under this key.
     * @param associated_data_bytes Authenticated, not encrypted.
     * @param data_bytes The message.
     * @param completion_token The completion token, of signature
     * `void(boost::system::error_code, result_type)`: the tag; on an error the zeroed tag (the
     * errors of `seal`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    auto async_seal(Executor const& completion_executor, std::span<std::uint8_t const> nonce_bytes,
                    std::span<std::uint8_t const> associated_data_bytes,
                    std::span<std::uint8_t> data_bytes, CompletionToken&& completion_token);

    /**
     * Opens a message in place: `data_bytes` holds the ciphertext before and the plaintext
     * after.
     *
     * When the tag does not match, or the backend fails, `data_bytes` is zeroed; a guard's
     * refusal leaves it untouched.
     *
     * @param nonce_bytes The nonce of the seal.
     * @param associated_data_bytes The associated data of the seal.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, `tag_size` bytes, which may lie anywhere, `data_bytes`
     * included.
     * @return Nothing; `invalid_state` moved from; `invalid_nonce_size`; `invalid_tag_size`;
     * `message_too_long`; `authentication_failed`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> open(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes, std::span<std::uint8_t> data_bytes,
        std::span<std::uint8_t const> tag_bytes) noexcept {
        secure::timing_guard const timing_scope;
        if constexpr (detail::asynchronous_backend_v<Backend>) {
            // WebCrypto has no such construction: the refusal names a native backend (design D6).
            detail::refuse_aead_on_asynchronous_backend<Backend>();
            return error::backend_failure;
        } else {
            auto const guard_result = guard_message(nonce_bytes, associated_data_bytes,
                                                    data_bytes.size(), tag_bytes.size());
            if (!guard_result) {
                return guard_result.error();
            }
            // The tag may lie in data, which decryption overwrites: a copy is checked.
            std::array<std::uint8_t, tag_size> expected_tag{};
            std::ranges::copy(tag_bytes, expected_tag.begin());
            auto const open_result =
                engine::open(state_, nonce_bytes, associated_data_bytes, data_bytes, expected_tag);
            if (!open_result) {
                secure::erase_secret(data_bytes);
                return open_result.error();
            }
            return {};
        }
    }

    /**
     * Opens a message in place, asynchronously: `open` run when the operation is initiated, its
     * result posted to `completion_executor`; the member form of
     * `secret_key_encryption::aead::async_open`, which calls it with the executor and the object
     * before this function's arguments.
     *
     * The object and the spans are the caller's until the completion; `data_bytes` holds the
     * plaintext at a successful completion, and is zeroed by a wrong tag. On a native backend
     * only: on a backend that completes by itself the call stops the build (design D6).
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile.
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param nonce_bytes The nonce of the seal.
     * @param associated_data_bytes The associated data of the seal.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, `tag_size` bytes.
     * @param completion_token The completion token, of signature `void(boost::system::error_code)`
     * (`open`'s errors).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    auto async_open(Executor const& completion_executor, std::span<std::uint8_t const> nonce_bytes,
                    std::span<std::uint8_t const> associated_data_bytes,
                    std::span<std::uint8_t> data_bytes, std::span<std::uint8_t const> tag_bytes,
                    CompletionToken&& completion_token);

private:
    // The asynchronous family's error completions make the empty object a move leaves.
    friend struct detail::async_access;

    basic_chacha20_poly1305() noexcept = default;

    // Every guard of a message, in the documented order: the state, the nonce, the tag
    // (open's; seal passes tag_size), the lengths. None reads a byte of the spans.
    [[nodiscard]] boost::system::result<void> guard_message(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes, std::size_t byte_count,
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
        if (detail::exceeds(byte_count, max_message_size) ||
            detail::exceeds(associated_data_bytes.size(), max_associated_data_size)) {
            return error::message_too_long;
        }
        return {};
    }

    state_type state_{};
    bool keyed_ = false;
};

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_AEAD_HPP
