// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `gcm<Cipher>`, AES-GCM over the cipher's backend.

 Its free synchronous forms (design D9, R23), `crypto::from_key<C>(key)`, `crypto::seal` and
 `crypto::open`, are declared in `factories.hpp` and `ciphers/aead.hpp`, which it includes.

 @see "AES-GCM", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_GCM_HPP
#define WEBCPP_CRYPTO_CIPHERS_GCM_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/aead.hpp>  // crypto::seal and crypto::open (design R23)
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/asynchronous.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/limits.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>  // crypto::from_key, which serves its from_key (design R23)

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
 * adding errors of their own after it; those that return report `backend_failure`, so that a
 * path the refusal missed fails closed.
 */
template <class Backend, std::size_t KeySize>
struct gcm_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_GCM(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> init(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> start(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> run(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> tag(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> check(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
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
 * AES-GCM (NIST SP 800-38D) with the key size of `Cipher`, on the backend `Cipher` names, which
 * must export GCM over its own AES: BearSSL or OpenSSL.
 *
 * A cipher that names no backend, as `aes256<>`, gives AES-GCM's default
 * (`default_backend_t<families::gcm>`), not the block cipher's.
 *
 * An object holds a key and the state of one message: it is used by one thread at a time,
 * and it is not shareable. A nonce is never reused under one key, and with random nonces, or
 * nonces other than 12 bytes, a key seals at most 2^32 messages (NIST SP 800-38D section 8.3).
 *
 * The incremental open reads the ciphertext twice: `authenticate` every piece, `verify` the
 * tag, then `decrypt` the same pieces; no plaintext reaches the caller before the tag matched.
 * The second pass must read the bytes the first read.
 *
 * @tparam Cipher `aes128<B>`, `aes192<B>` or `aes256<B>`.
 */
template <class Cipher>
class gcm {
    using backend = detail::resolved_backend_t<typename Cipher::named_backend_type, families::gcm>;
    using state_type = detail::gcm_state<backend, Cipher::key_size>;
    using engine = detail::gcm_engine<backend, Cipher::key_size>;

public:
    /** The block cipher. */
    using cipher_type = Cipher;
    /** The backend: the one `Cipher` names, or, where it names none, AES-GCM's default. */
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
    /** The recommended nonce size. */
    static constexpr std::size_t iv_size = 12;
    /** The longest nonce accepted, OpenSSL's limit, applied on every backend. */
    static constexpr std::size_t max_iv_size = 128;
    /** The longest message, 2^36 - 32 bytes (NIST SP 800-38D section 5.2.1.1). */
    static constexpr std::uint64_t max_message_size = (std::uint64_t{1} << 36U) - 32;
    /** The longest associated data, 2^61 - 1 bytes (the same section, 2^64 - 1 bits). */
    static constexpr std::uint64_t max_additional_data_size = (std::uint64_t{1} << 61U) - 1;

    /**
     * Expands a key into a new object.
     *
     * @param key_bytes `key_size` bytes.
     * @return The object; `invalid_key_size`, `errc::not_enough_memory` or `backend_failure`.
     */
    [[nodiscard]] static boost::system::result<gcm> from_key(
        std::span<std::uint8_t const> key_bytes) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(!detail::asynchronous_backend_v<backend>,
                      "webcpp::crypto: from_key on this backend completes asynchronously: call "
                      "async_from_key.");
        if constexpr (detail::asynchronous_backend_v<backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
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
    }

    /**
     * Expands a key into a new object, asynchronously: `from_key` run when the operation is
     * initiated, its result posted to `completion_executor`; the member form of
     * `crypto::async_from_key<gcm>(executor, key_bytes, token)`, which calls it.
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
     * `void(boost::system::error_code, gcm)`; on an error the object is empty, and every member
     * refuses with `invalid_state` (`invalid_key_size`, `errc::not_enough_memory`,
     * `backend_failure`).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    static auto async_from_key(Executor const& completion_executor,
                               std::span<std::uint8_t const> key_bytes,
                               CompletionToken&& completion_token);

    /**
     * Moves the key; a message in progress is abandoned, and the source is wiped and empty.
     *
     * Moving an empty object gives an empty one: BearSSL's move initialises the destination's
     * context through the schedule's vtable, which a wiped state does not have.
     *
     * @param moved_source The source, empty afterwards.
     */
    gcm(gcm&& moved_source) noexcept : keyed_(std::exchange(moved_source.keyed_, false)) {
        detail::timing_guard const timing_scope;
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
        detail::timing_guard const timing_scope;
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
     * The nonce and the associated data are read before the first byte of `data_bytes` is written,
     * so they may lie in `data_bytes`.
     *
     * When the backend fails, `data_bytes` is zeroed, as a failed open's is; a guard's refusal
     * leaves it untouched.
     *
     * @param nonce_bytes 1 to `max_iv_size` bytes, never reused under this key; 12 recommended.
     * @param associated_data_bytes Authenticated, not encrypted.
     * @param data_bytes The message.
     * @return The tag; `invalid_state` moved from or during an incremental message, which
     * goes on; `invalid_iv_size`; `message_too_long`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<result_type> seal(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes,
        std::span<std::uint8_t> data_bytes) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(
            !detail::asynchronous_backend_v<backend>,
            "webcpp::crypto: seal on this backend completes asynchronously: call async_seal.");
        if constexpr (detail::asynchronous_backend_v<backend>) {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        } else {
            auto const guard_result =
                guard_message(nonce_bytes, associated_data_bytes, data_bytes.size(), tag_size);
            if (!guard_result) {
                return guard_result.error();
            }
            auto const start_result =
                engine::start(state_, true, nonce_bytes, associated_data_bytes);
            auto const run_result = start_result ? engine::run(state_, data_bytes) : start_result;
            result_type tag_bytes{};
            auto const tag_result = run_result ? engine::tag(state_, tag_bytes) : run_result;
            if (!tag_result) {
                // A message without a tag is not to be sent: data is zeroed, and nothing of the
                // failed message stays in the context, as after an incremental one.
                detail::wipe(data_bytes.data(), data_bytes.size());
                engine::abandon(state_);
                return tag_result.error();
            }
            return tag_bytes;
        }
    }

    /**
     * Seals a message in place, asynchronously: `seal` run when the operation is initiated, its
     * result posted to `completion_executor`; the member form of
     * `crypto::async_seal(executor, aead, nonce_bytes, associated_data_bytes, data_bytes, token)`,
     * which calls it.
     *
     * The object and the spans are the caller's until the completion; `data_bytes` holds the
     * ciphertext at the completion.
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param nonce_bytes 1 to `max_iv_size` bytes, never reused under this key.
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
     * Opens a message in place: `data_bytes` holds the ciphertext before and the plaintext after.
     *
     * While it runs, the decrypted bytes are in `data_bytes` before the tag is checked; when the
     * tag does not match, or the backend fails, `data_bytes` is zeroed. A guard's refusal leaves it
     * untouched.
     *
     * @param nonce_bytes The nonce of the seal.
     * @param associated_data_bytes The associated data of the seal.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, 16 bytes, which may lie anywhere, `data_bytes` included.
     * @return Nothing; `invalid_state` moved from or during an incremental message, which
     * goes on; `invalid_iv_size`; `invalid_tag_size`; `message_too_long`;
     * `authentication_failed`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> open(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes, std::span<std::uint8_t> data_bytes,
        std::span<std::uint8_t const> tag_bytes) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(
            !detail::asynchronous_backend_v<backend>,
            "webcpp::crypto: open on this backend completes asynchronously: call async_open.");
        if constexpr (detail::asynchronous_backend_v<backend>) {
            // Never compiled into a program: the assertion above stopped the build.
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
            auto const start_result =
                engine::start(state_, false, nonce_bytes, associated_data_bytes);
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
    }

    /**
     * Opens a message in place, asynchronously: `open` run when the operation is initiated, its
     * result posted to `completion_executor`; the member form of `crypto::async_open`, which calls
     * it with the executor and the object before this function's arguments.
     *
     * The object and the spans are the caller's until the completion; `data_bytes` holds the
     * plaintext at a successful completion.
     *
     * Declared here and defined in `<webcpp/crypto/async.hpp>`, which a program includes to call
     * it, with `<library>/webcpp/asio//asio` in its Jamfile; without it, the call is the compiler's
     * "deduced return type used before it is defined".
     *
     * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
     * @tparam CompletionToken Any completion token for the signature `completion_token` states.
     * @param completion_executor The executor the completion is posted to.
     * @param nonce_bytes The nonce of the seal.
     * @param associated_data_bytes The associated data of the seal.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The seal's tag, 16 bytes.
     * @param completion_token The completion token, of signature `void(boost::system::error_code)`
     * (`open`'s errors).
     * @return What the completion token's `async_result` gives.
     */
    template <class Executor, class CompletionToken>
    auto async_open(Executor const& completion_executor, std::span<std::uint8_t const> nonce_bytes,
                    std::span<std::uint8_t const> associated_data_bytes,
                    std::span<std::uint8_t> data_bytes, std::span<std::uint8_t const> tag_bytes,
                    CompletionToken&& completion_token);

    /**
     * Begins an incremental seal: the nonce and the whole associated data first, both read
     * before this returns.
     *
     * Any error of `begin_seal`, `update` or `result` ends the message, which is abandoned:
     * the pieces already encrypted have no tag and are not to be sent.
     *
     * @param nonce_bytes 1 to `max_iv_size` bytes, never reused under this key.
     * @param associated_data_bytes Authenticated, not encrypted.
     * @return Nothing; `invalid_state` moved from or with a message in progress, which ends
     * it; `invalid_iv_size`; `message_too_long`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> begin_seal(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes) noexcept {
        detail::timing_guard const timing_scope;
        if (!keyed_) {
            return error::invalid_state;
        }
        if (phase_ != phase::none) {
            abandon();
            return error::invalid_state;
        }
        auto const guard_result = guard_message(nonce_bytes, associated_data_bytes, 0, tag_size);
        if (!guard_result) {
            return guard_result.error();
        }
        auto const start_result = engine::start(state_, true, nonce_bytes, associated_data_bytes);
        if (!start_result) {
            engine::abandon(state_);
            return start_result.error();
        }
        phase_ = phase::sealing;
        message_bytes_ = 0;
        return {};
    }

    /**
     * Encrypts the next piece of the message in place.
     *
     * When the backend fails, the piece is zeroed and the message ends; a refusal of the
     * piece's size leaves it untouched.
     *
     * @param data_bytes The piece, of any size, empty included.
     * @return Nothing; `invalid_state` without a seal, which ends an open in progress;
     * `message_too_long` when the pieces pass `max_message_size`, which ends the message;
     * `backend_failure`, which ends it.
     */
    [[nodiscard]] boost::system::result<void> update(std::span<std::uint8_t> data_bytes) noexcept {
        detail::timing_guard const timing_scope;
        auto const phase_result = require_phase(phase::sealing);
        if (!phase_result) {
            return phase_result.error();
        }
        if (detail::exceeds(data_bytes.size(), max_message_size - message_bytes_)) {
            abandon();
            return error::message_too_long;
        }
        auto const run_result = engine::run(state_, data_bytes);
        if (!run_result) {
            detail::wipe(data_bytes.data(), data_bytes.size());
            abandon();
            return run_result.error();
        }
        message_bytes_ += data_bytes.size();
        return {};
    }

    /**
     * Ends the message with its tag.
     *
     * @return The tag; `invalid_state` without a seal, which ends an open in progress;
     * `backend_failure`, which ends the seal too.
     */
    [[nodiscard]] boost::system::result<result_type> result() noexcept {
        detail::timing_guard const timing_scope;
        auto const phase_result = require_phase(phase::sealing);
        if (!phase_result) {
            return phase_result.error();
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

    /**
     * Begins an incremental open: the nonce and the whole associated data first, both read before
     * this returns, the nonce kept for the second pass.
     *
     * The open takes two passes over the ciphertext: `authenticate` reads every piece, `verify`
     * checks the tag, and only then `decrypt` turns the same pieces into plaintext, which
     * `end_open` ends. Any error of these calls ends the message.
     *
     * @param nonce_bytes The nonce of the seal, 1 to `max_iv_size` bytes.
     * @param associated_data_bytes The associated data of the seal.
     * @return Nothing; `invalid_state` moved from or with a message in progress, which ends
     * it; `invalid_iv_size`; `message_too_long`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<void> begin_open(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes) noexcept {
        detail::timing_guard const timing_scope;
        if (!keyed_) {
            return error::invalid_state;
        }
        if (phase_ != phase::none) {
            abandon();
            return error::invalid_state;
        }
        auto const guard_result = guard_message(nonce_bytes, associated_data_bytes, 0, tag_size);
        if (!guard_result) {
            return guard_result.error();
        }
        std::ranges::copy(nonce_bytes, nonce_.begin());
        iv_size_ = nonce_bytes.size();
        auto const start_result = engine::start(state_, false, nonce_bytes, associated_data_bytes);
        if (!start_result) {
            engine::abandon(state_);
            end_message();
            return start_result.error();
        }
        phase_ = phase::authenticating;
        message_bytes_ = 0;
        decrypted_bytes_ = 0;
        return {};
    }

    /**
     * The first pass: authenticates the next piece of the ciphertext, which is read and never
     * written.
     *
     * The piece is decrypted in blocks of 256 bytes into a buffer of this call, which is wiped
     * after each block: no plaintext leaves it.
     *
     * @param ciphertext_piece The piece, of any size, empty included.
     * @return Nothing; `invalid_state` outside the first pass, which ends a message in
     * progress; `message_too_long` when the pieces pass `max_message_size`, which ends the
     * message; `backend_failure`, which ends it.
     */
    [[nodiscard]] boost::system::result<void> authenticate(
        std::span<std::uint8_t const> ciphertext_piece) noexcept {
        detail::timing_guard const timing_scope;
        auto const phase_result = require_phase(phase::authenticating);
        if (!phase_result) {
            return phase_result.error();
        }
        if (detail::exceeds(ciphertext_piece.size(), max_message_size - message_bytes_)) {
            abandon();
            return error::message_too_long;
        }
        std::array<std::uint8_t, scratch_size> scratch_bytes{};
        for (std::size_t piece_start = 0; piece_start < ciphertext_piece.size();
             piece_start += scratch_size) {
            std::size_t const block_size =
                (std::min)(scratch_size, ciphertext_piece.size() - piece_start);
            std::copy_n(ciphertext_piece.data() + piece_start, block_size, scratch_bytes.data());
            auto const run_result = engine::run(state_, std::span(scratch_bytes).first(block_size));
            detail::wipe(scratch_bytes.data(), block_size);
            if (!run_result) {
                abandon();
                return run_result.error();
            }
        }
        message_bytes_ += ciphertext_piece.size();
        return {};
    }

    /**
     * Ends the first pass: checks the tag of the pieces authenticated, and on a match begins
     * the second pass.
     *
     * @param tag_bytes The seal's tag, 16 bytes.
     * @return Nothing; `invalid_state` outside the first pass, which ends a message in
     * progress; `invalid_tag_size`, `authentication_failed` and `backend_failure`, each of
     * which ends the message.
     */
    [[nodiscard]] boost::system::result<void> verify(
        std::span<std::uint8_t const> tag_bytes) noexcept {
        detail::timing_guard const timing_scope;
        auto const phase_result = require_phase(phase::authenticating);
        if (!phase_result) {
            return phase_result.error();
        }
        if (tag_bytes.size() != tag_size) {
            abandon();
            return error::invalid_tag_size;
        }
        std::array<std::uint8_t, tag_size> expected_tag{};
        std::ranges::copy(tag_bytes, expected_tag.begin());
        auto const check_result = engine::check(state_, expected_tag);
        if (!check_result) {
            abandon();
            return check_result.error();
        }
        // GCM's keystream depends on the key and the nonce alone: the second pass needs no
        // associated data, and the tag the engine computes in it is never read.
        engine::abandon(state_);
        auto const start_result =
            engine::start(state_, false, std::span(nonce_).first(iv_size_), {});
        if (!start_result) {
            abandon();
            return start_result.error();
        }
        phase_ = phase::decrypting;
        decrypted_bytes_ = 0;
        return {};
    }

    /**
     * The second pass: decrypts the next piece in place, the bytes `authenticate` read in the
     * same place of the message.
     *
     * When the backend fails, the piece is zeroed and the message ends; a refusal of the
     * piece's size leaves it untouched.
     *
     * @param data_piece The piece: ciphertext before, plaintext after.
     * @return Nothing; `invalid_state` before `verify` matched, which ends a message in
     * progress; `invalid_input_size` when the pieces pass the bytes authenticated, which ends
     * the message; `backend_failure`, which ends it.
     */
    [[nodiscard]] boost::system::result<void> decrypt(std::span<std::uint8_t> data_piece) noexcept {
        detail::timing_guard const timing_scope;
        auto const phase_result = require_phase(phase::decrypting);
        if (!phase_result) {
            return phase_result.error();
        }
        if (data_piece.size() > message_bytes_ - decrypted_bytes_) {
            abandon();
            return error::invalid_input_size;
        }
        auto const run_result = engine::run(state_, data_piece);
        if (!run_result) {
            detail::wipe(data_piece.data(), data_piece.size());
            abandon();
            return run_result.error();
        }
        decrypted_bytes_ += data_piece.size();
        return {};
    }

    /**
     * Ends the open, whose message's state is wiped.
     *
     * @return Nothing; `invalid_state` outside the second pass, which ends a message in
     * progress; `invalid_input_size` when fewer bytes were decrypted than authenticated,
     * which ends the message too.
     */
    [[nodiscard]] boost::system::result<void> end_open() noexcept {
        detail::timing_guard const timing_scope;
        auto const phase_result = require_phase(phase::decrypting);
        if (!phase_result) {
            return phase_result.error();
        }
        bool const whole_message = decrypted_bytes_ == message_bytes_;
        abandon();
        if (!whole_message) {
            return error::invalid_input_size;
        }
        return {};
    }

private:
    // The phases of the incremental message: none, the seal, the open's first and second pass.
    enum class phase : std::uint8_t { none, sealing, authenticating, decrypting };

    // The bytes authenticate decrypts at once into its own buffer.
    static constexpr std::size_t scratch_size = 256;

    // The asynchronous family's error completions make the empty object a move leaves.
    friend struct detail::async_access;

    gcm() noexcept = default;

    // A call of the incremental machine in `expected_phase`: outside it, `invalid_state`, which
    // ends a message in another phase.
    [[nodiscard]] boost::system::result<void> require_phase(phase expected_phase) noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (phase_ != expected_phase) {
            if (phase_ != phase::none) {
                abandon();
            }
            return error::invalid_state;
        }
        return {};
    }

    // The message's state is wiped by the engine, the key kept; no message is in progress.
    void abandon() noexcept {
        engine::abandon(state_);
        end_message();
    }

    // Before a move: a message in progress is abandoned through the engine, so that a
    // backend whose move copies its context whole (OpenSSL's) carries none of it into the
    // destination.
    void abandon_message() noexcept {
        if (phase_ != phase::none) {
            abandon();
        }
    }

    // Every guard of a message, in the documented order: the state, the nonce, the tag
    // (open's; seal passes tag_size), the lengths. None reads a byte of the spans.
    [[nodiscard]] boost::system::result<void> guard_message(
        std::span<std::uint8_t const> nonce_bytes,
        std::span<std::uint8_t const> associated_data_bytes, std::size_t byte_count,
        std::size_t tag_bytes) const noexcept {
        if (!keyed_ || phase_ != phase::none) {
            return error::invalid_state;
        }
        if (nonce_bytes.empty() || nonce_bytes.size() > max_iv_size) {
            return error::invalid_iv_size;
        }
        if (tag_bytes != tag_size) {
            return error::invalid_tag_size;
        }
        if (detail::exceeds(byte_count, max_message_size) ||
            detail::exceeds(associated_data_bytes.size(), max_additional_data_size)) {
            return error::message_too_long;
        }
        return {};
    }

    // No message is in progress; the kept nonce is wiped and the counters zeroed.
    void end_message() noexcept {
        phase_ = phase::none;
        detail::wipe(nonce_.data(), nonce_.size());
        iv_size_ = 0;
        message_bytes_ = 0;
        decrypted_bytes_ = 0;
    }

    state_type state_{};
    bool keyed_ = false;
    phase phase_ = phase::none;
    // The open's nonce, kept for its second pass.
    std::array<std::uint8_t, max_iv_size> nonce_{};
    std::size_t iv_size_ = 0;
    // The bytes sealed, or authenticated by the open's first pass.
    std::uint64_t message_bytes_ = 0;
    // The bytes decrypted by the open's second pass.
    std::uint64_t decrypted_bytes_ = 0;
};

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_GCM_HPP
