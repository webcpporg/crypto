// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `gcm<Cipher>`, AES-GCM over the cipher's backend.

 @see "AES-GCM", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_GCM_HPP
#define WEBCPP_CRYPTO_CIPHERS_GCM_HPP

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
#include <type_traits>
#include <utility>

namespace webcpp::crypto::detail {

/**
 * What a `ciphers::gcm` stores on a backend whose header does not specialise it: nothing, since
 * its engine refuses the backend where the family is called.
 */
template <class Backend, std::size_t KeySize>
struct gcm_state {};

/**
 * GCM's engine on a backend whose header does not specialise it: the family's refusal, which
 * names what the program needs (`detail/capabilities.hpp`). Its functions are never called: the
 * refusal stops the build where the class is instantiated, and they keep the compiler from
 * adding errors of their own after it.
 */
template <class Backend, std::size_t KeySize>
struct gcm_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_GCM(Backend);

    /** Never called. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> init(Arguments&&... /*arguments*/) noexcept {
        return {};
    }

    /** Never called. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> start(Arguments&&... /*arguments*/) noexcept {
        return {};
    }

    /** Never called. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> run(Arguments&&... /*arguments*/) noexcept {
        return {};
    }

    /** Never called. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> tag(Arguments&&... /*arguments*/) noexcept {
        return {};
    }

    /** Never called. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> check(Arguments&&... /*arguments*/) noexcept {
        return {};
    }

    /** Never called. */
    template <class... Arguments>
    static void move(Arguments&&... /*arguments*/) noexcept {}

    /** Never called. */
    template <class... Arguments>
    static void abandon(Arguments&&... /*arguments*/) noexcept {}

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::ciphers {

/**
 * AES-GCM (NIST SP 800-38D) with the key size of `Cipher`, on the backend of `Cipher`, which
 * must export GCM over its own AES: BearSSL or OpenSSL.
 *
 * An object holds a key and the state of one message: it is used by one thread at a time,
 * and it is not shareable. An IV is never reused under one key, and with random IVs, or IVs
 * other than 12 bytes, a key seals at most 2^32 messages (NIST SP 800-38D section 8.3).
 *
 * @tparam Cipher `aes128<B>`, `aes192<B>` or `aes256<B>`.
 */
template <class Cipher>
class gcm {
    using backend = Cipher::backend_type;
    using state_type = detail::gcm_state<backend, Cipher::key_size>;
    using engine = detail::gcm_engine<backend, Cipher::key_size>;

public:
    /** The block cipher. */
    using cipher_type = Cipher;
    /** The backend. */
    using backend_type = backend;
    /** The family of the capability table, `families::gcm`, which `supports_v` reads. */
    using family_type = families::gcm;
    /**
     * The algorithm of the capability table: `tags::aes128_gcm`, `tags::aes192_gcm` or
     * `tags::aes256_gcm`, by the key's size.
     */
    using name_type = std::conditional_t<
        Cipher::key_size == 16, tags::aes128_gcm,
        std::conditional_t<Cipher::key_size == 24, tags::aes192_gcm, tags::aes256_gcm>>;
    /** The tag, Boost.Hash2's digest of 16 bytes. */
    using result_type = boost::hash2::digest<16>;
    /** The key's size in bytes. */
    static constexpr std::size_t key_size = Cipher::key_size;
    /** The tag's size. */
    static constexpr std::size_t tag_size = 16;
    /** The recommended IV size. */
    static constexpr std::size_t iv_size = 12;
    /** The longest IV accepted, OpenSSL's limit, applied on every backend. */
    static constexpr std::size_t max_iv_size = 128;
    /** The longest message, 2^36 - 32 bytes (NIST SP 800-38D section 5.2.1.1). */
    static constexpr std::uint64_t max_message_size = (std::uint64_t{1} << 36U) - 32;
    /** The longest additional data, 2^61 - 1 bytes (the same section, 2^64 - 1 bits). */
    static constexpr std::uint64_t max_additional_data_size = (std::uint64_t{1} << 61U) - 1;

    /**
     * Expands a key into a new object.
     *
     * @param key_bytes `key_size` bytes.
     * @return The object; `invalid_key_size`, `errc::not_enough_memory` or `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<gcm> make(
        std::span<std::uint8_t const> key_bytes) noexcept {
        if (key_bytes.size() != key_size) {
            return error::invalid_key_size;
        }
        gcm made_object;
        auto const key_result = engine::init(made_object.state_, key_bytes);
        if (!key_result) {
            return key_result.error();
        }
        made_object.keyed_ = true;
        return made_object;
    }

    /**
     * Moves the key; a message in progress is abandoned, and the source is wiped and empty.
     *
     * Moving an empty object gives an empty one: BearSSL's move initialises the destination's
     * context through the schedule's vtable, which a wiped state does not have.
     *
     * @param moved_source The source, empty afterwards.
     */
    gcm(gcm&& moved_source) noexcept : keyed_(std::exchange(moved_source.keyed_, false)) {
        if (keyed_) {
            moved_source.abandon_message();
            engine::move(state_, moved_source.state_);
        }
        moved_source.end_message();
    }

    /**
     * Moves the key over this one, which is wiped first; a message in progress on either
     * side is abandoned.
     *
     * @param moved_source The source, empty afterwards.
     * @return This object.
     */
    gcm& operator=(gcm&& moved_source) noexcept {
        if (this != &moved_source) {
            engine::reset(state_);
            keyed_ = std::exchange(moved_source.keyed_, false);
            if (keyed_) {
                moved_source.abandon_message();
                engine::move(state_, moved_source.state_);
            }
            end_message();
            moved_source.end_message();
        }
        return *this;
    }

    /** Not copyable: a key has one owner, which wipes it. */
    gcm(gcm const&) = delete;
    /** Not copyable: a key has one owner, which wipes it. */
    gcm& operator=(gcm const&) = delete;

    /** Wipes the key and the state. */
    ~gcm() { engine::reset(state_); }

    /**
     * Seals a message in place: `data_bytes` holds the plaintext before and the ciphertext after.
     *
     * The IV and the additional data are read before the first byte of `data_bytes` is written, so
     * they may lie in `data_bytes`.
     *
     * @param iv_bytes 1 to `max_iv_size` bytes, never reused under this key; 12 recommended.
     * @param additional_data_bytes Authenticated, not encrypted.
     * @param data_bytes The message.
     * @return The tag; `invalid_state` moved from or during an incremental message, which
     * goes on; `invalid_iv_size`; `message_too_long`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<result_type> seal(
        std::span<std::uint8_t const> iv_bytes, std::span<std::uint8_t const> additional_data_bytes,
        std::span<std::uint8_t> data_bytes) noexcept {
        auto const guard_result =
            guard_message(iv_bytes, additional_data_bytes, data_bytes.size(), tag_size);
        if (!guard_result) {
            return guard_result.error();
        }
        auto const start_result = engine::start(state_, true, iv_bytes, additional_data_bytes);
        auto const run_result = start_result ? engine::run(state_, data_bytes) : start_result;
        result_type tag_bytes{};
        auto const tag_result = run_result ? engine::tag(state_, tag_bytes) : run_result;
        if (!tag_result) {
            // Nothing of the failed message stays in the context, as after an incremental one.
            engine::abandon(state_);
            return tag_result.error();
        }
        return tag_bytes;
    }

    /**
     * Opens a message in place: `data_bytes` holds the ciphertext before and the plaintext after.
     *
     * While it runs, the decrypted bytes are in `data_bytes` before the tag is checked; when the
     * tag does not match, or the backend fails, `data_bytes` is zeroed. A guard's refusal leaves it
     * untouched.
     *
     * @param iv_bytes The IV of the seal.
     * @param additional_data_bytes The additional data of the seal.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, 16 bytes, which may lie anywhere, `data_bytes` included.
     * @return Nothing; `invalid_state` moved from or during an incremental message, which
     * goes on; `invalid_iv_size`; `invalid_tag_size`; `message_too_long`;
     * `authentication_failed`; `backend_failure`.
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
        auto const start_result = engine::start(state_, false, iv_bytes, additional_data_bytes);
        auto const open_result = start_result ? engine::run(state_, data_bytes) : start_result;
        auto const tag_check_result =
            open_result ? engine::check(state_, expected_tag) : open_result;
        if (!tag_check_result) {
            detail::wipe(data_bytes.data(), data_bytes.size());
            engine::abandon(state_);
            return tag_check_result.error();
        }
        return {};
    }

    /**
     * Begins an incremental seal: the IV and the whole additional data first, both read
     * before this returns.
     *
     * Any error of `begin_seal`, `update` or `result` ends the message, which is abandoned:
     * the pieces already encrypted have no tag and are not to be sent.
     *
     * @param iv_bytes 1 to `max_iv_size` bytes, never reused under this key.
     * @param additional_data_bytes Authenticated, not encrypted.
     * @return Nothing; `invalid_state` moved from or with a message in progress, which ends
     * it; `invalid_iv_size`; `message_too_long`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> begin_seal(
        std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> additional_data_bytes) noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (in_message_) {
            abandon();
            return error::invalid_state;
        }
        auto const guard_result = guard_message(iv_bytes, additional_data_bytes, 0, tag_size);
        if (!guard_result) {
            return guard_result.error();
        }
        auto const start_result = engine::start(state_, true, iv_bytes, additional_data_bytes);
        if (!start_result) {
            engine::abandon(state_);
            return start_result.error();
        }
        in_message_ = true;
        message_bytes_ = 0;
        return {};
    }

    /**
     * Encrypts the next piece of the message in place.
     *
     * @param data_bytes The piece, of any size, empty included.
     * @return Nothing; `invalid_state` without a message; `message_too_long` when the pieces
     * pass `max_message_size`, which ends the message; `backend_failure`, which ends it.
     */
    [[nodiscard]] boost::system::result<void> update(std::span<std::uint8_t> data_bytes) noexcept {
        if (!keyed_ || !in_message_) {
            return error::invalid_state;
        }
        if (detail::exceeds(data_bytes.size(), max_message_size - message_bytes_)) {
            abandon();
            return error::message_too_long;
        }
        auto const run_result = engine::run(state_, data_bytes);
        if (!run_result) {
            abandon();
            return run_result.error();
        }
        message_bytes_ += data_bytes.size();
        return {};
    }

    /**
     * Ends the message with its tag.
     *
     * @return The tag; `invalid_state` without a message; `backend_failure`, which ends it
     * too.
     */
    [[nodiscard]] boost::system::result<result_type> result() noexcept {
        if (!keyed_ || !in_message_) {
            return error::invalid_state;
        }
        result_type tag_bytes{};
        auto const tag_result = engine::tag(state_, tag_bytes);
        end_message();
        if (!tag_result) {
            engine::abandon(state_);
            return tag_result.error();
        }
        return tag_bytes;
    }

private:
    gcm() noexcept = default;

    // The message's state is wiped by the engine, the key kept; no message is in progress.
    void abandon() noexcept {
        engine::abandon(state_);
        end_message();
    }

    // Before a move: a message in progress is abandoned through the engine, so that a
    // backend whose move copies its context whole (OpenSSL's) carries none of it into the
    // destination.
    void abandon_message() noexcept {
        if (in_message_) {
            abandon();
        }
    }

    // Every guard of a message, in the documented order: the state, the IV, the tag
    // (open's; seal passes tag_size), the lengths. None reads a byte of the spans.
    [[nodiscard]] boost::system::result<void> guard_message(
        std::span<std::uint8_t const> iv_bytes, std::span<std::uint8_t const> additional_data_bytes,
        std::size_t byte_count, std::size_t tag_bytes) const noexcept {
        if (!keyed_ || in_message_) {
            return error::invalid_state;
        }
        if (iv_bytes.empty() || iv_bytes.size() > max_iv_size) {
            return error::invalid_iv_size;
        }
        if (tag_bytes != tag_size) {
            return error::invalid_tag_size;
        }
        if (detail::exceeds(byte_count, max_message_size) ||
            detail::exceeds(additional_data_bytes.size(), max_additional_data_size)) {
            return error::message_too_long;
        }
        return {};
    }

    void end_message() noexcept {
        in_message_ = false;
        message_bytes_ = 0;
    }

    state_type state_{};
    bool keyed_ = false;
    bool in_message_ = false;
    std::uint64_t message_bytes_ = 0;
};

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_GCM_HPP
