// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `gcm<Cipher>`, AES-GCM over the cipher's backend.

 @see "AES-GCM", in the guide.
*/
#ifndef WEBCPP_CRYPTO_GCM_HPP
#define WEBCPP_CRYPTO_GCM_HPP

#include <webcpp/crypto/config.hpp>

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

namespace webcpp::crypto {

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
     * @param key `key_size` bytes.
     * @return The object; `invalid_key_size`, `errc::not_enough_memory` or `backend_failure`.
     */
    static boost::system::result<gcm> make(std::span<std::uint8_t const> key) noexcept {
        if (key.size() != key_size) {
            return error::invalid_key_size;
        }
        gcm made;
        auto const keyed = engine::init(made.state_, key);
        if (!keyed) {
            return keyed.error();
        }
        made.keyed_ = true;
        return made;
    }

    /**
     * Moves the key; a message in progress is abandoned, and the source is wiped and empty.
     *
     * Moving an empty object gives an empty one: BearSSL's move initialises the destination's
     * context through the schedule's vtable, which a wiped state does not have (I1).
     *
     * @param other The source, empty afterwards.
     */
    gcm(gcm&& other) noexcept : keyed_(std::exchange(other.keyed_, false)) {
        if (keyed_) {
            other.abandon_message();
            engine::move(state_, other.state_);
        }
        other.end_message();
    }

    /**
     * Moves the key over this one, which is wiped first; a message in progress on either
     * side is abandoned.
     *
     * @param other The source, empty afterwards.
     * @return This object.
     */
    gcm& operator=(gcm&& other) noexcept {
        if (this != &other) {
            engine::reset(state_);
            keyed_ = std::exchange(other.keyed_, false);
            if (keyed_) {
                other.abandon_message();
                engine::move(state_, other.state_);
            }
            end_message();
            other.end_message();
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
     * Seals a message in place: `data` holds the plaintext before and the ciphertext after.
     *
     * The IV and the additional data are read before the first byte of `data` is written, so
     * they may lie in `data`.
     *
     * @param iv 1 to `max_iv_size` bytes, never reused under this key; 12 recommended.
     * @param additional_data Authenticated, not encrypted.
     * @param data The message.
     * @return The tag; `invalid_state` moved from or during an incremental message, which
     * goes on; `invalid_iv_size`; `message_too_long`; `backend_failure`.
     */
    boost::system::result<result_type> seal(std::span<std::uint8_t const> iv,
                                            std::span<std::uint8_t const> additional_data,
                                            std::span<std::uint8_t> data) noexcept {
        auto const refused = guard_message(iv, additional_data, data.size(), tag_size);
        if (!refused) {
            return refused.error();
        }
        auto const started = engine::start(state_, true, iv, additional_data);
        if (!started) {
            return started.error();
        }
        auto const ran = engine::run(state_, data);
        if (!ran) {
            return ran.error();
        }
        result_type tag{};
        auto const tagged = engine::tag(state_, tag);
        if (!tagged) {
            return tagged.error();
        }
        return tag;
    }

    /**
     * Opens a message in place: `data` holds the ciphertext before and the plaintext after.
     *
     * While it runs, the decrypted bytes are in `data` before the tag is checked; when the
     * tag does not match, or the backend fails, `data` is zeroed. A guard's refusal leaves it
     * untouched.
     *
     * @param iv The IV of the seal.
     * @param additional_data The additional data of the seal.
     * @param data The ciphertext.
     * @param tag The seal's tag, 16 bytes, which may lie anywhere, `data` included.
     * @return Nothing; `invalid_state` moved from or during an incremental message, which
     * goes on; `invalid_iv_size`; `invalid_tag_size`; `message_too_long`;
     * `authentication_failed`; `backend_failure`.
     */
    boost::system::result<void> open(std::span<std::uint8_t const> iv,
                                     std::span<std::uint8_t const> additional_data,
                                     std::span<std::uint8_t> data,
                                     std::span<std::uint8_t const> tag) noexcept {
        auto const refused = guard_message(iv, additional_data, data.size(), tag.size());
        if (!refused) {
            return refused.error();
        }
        // The tag may lie in data, which decryption overwrites: a copy is checked.
        std::array<std::uint8_t, tag_size> expected{};
        std::ranges::copy(tag, expected.begin());
        auto const started = engine::start(state_, false, iv, additional_data);
        auto const opened = started ? engine::run(state_, data) : started;
        auto const checked = opened ? engine::check(state_, expected) : opened;
        if (!checked) {
            detail::wipe(data.data(), data.size());
            return checked.error();
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
     * @param iv 1 to `max_iv_size` bytes, never reused under this key.
     * @param additional_data Authenticated, not encrypted.
     * @return Nothing; `invalid_state` moved from or with a message in progress, which ends
     * it; `invalid_iv_size`; `message_too_long`; `backend_failure`.
     */
    boost::system::result<void> begin_seal(std::span<std::uint8_t const> iv,
                                           std::span<std::uint8_t const> additional_data) noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (in_message_) {
            abandon();
            return error::invalid_state;
        }
        auto const refused = guard_message(iv, additional_data, 0, tag_size);
        if (!refused) {
            return refused.error();
        }
        auto const started = engine::start(state_, true, iv, additional_data);
        if (!started) {
            engine::abandon(state_);
            return started.error();
        }
        in_message_ = true;
        message_bytes_ = 0;
        return {};
    }

    /**
     * Encrypts the next piece of the message in place.
     *
     * @param data The piece, of any size, empty included.
     * @return Nothing; `invalid_state` without a message; `message_too_long` when the pieces
     * pass `max_message_size`, which ends the message; `backend_failure`, which ends it.
     */
    boost::system::result<void> update(std::span<std::uint8_t> data) noexcept {
        if (!keyed_ || !in_message_) {
            return error::invalid_state;
        }
        if (detail::exceeds(data.size(), max_message_size - message_bytes_)) {
            abandon();
            return error::message_too_long;
        }
        auto const ran = engine::run(state_, data);
        if (!ran) {
            abandon();
            return ran.error();
        }
        message_bytes_ += data.size();
        return {};
    }

    /**
     * Ends the message with its tag.
     *
     * @return The tag; `invalid_state` without a message; `backend_failure`, which ends it
     * too.
     */
    boost::system::result<result_type> result() noexcept {
        if (!keyed_ || !in_message_) {
            return error::invalid_state;
        }
        result_type tag{};
        auto const tagged = engine::tag(state_, tag);
        end_message();
        if (!tagged) {
            engine::abandon(state_);
            return tagged.error();
        }
        return tag;
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

    // Every guard of a message, in spec section 2.4's order: the state, the IV, the tag
    // (open's; seal passes tag_size), the lengths. None reads a byte of the spans.
    [[nodiscard]] boost::system::result<void> guard_message(
        std::span<std::uint8_t const> iv, std::span<std::uint8_t const> additional_data,
        std::size_t size, std::size_t tag) const noexcept {
        if (!keyed_ || in_message_) {
            return error::invalid_state;
        }
        if (iv.empty() || iv.size() > max_iv_size) {
            return error::invalid_iv_size;
        }
        if (tag != tag_size) {
            return error::invalid_tag_size;
        }
        if (detail::exceeds(size, max_message_size) ||
            detail::exceeds(additional_data.size(), max_additional_data_size)) {
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

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_GCM_HPP
