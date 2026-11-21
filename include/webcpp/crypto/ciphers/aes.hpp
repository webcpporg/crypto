// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The AES block cipher, `aes128`, `aes192` and `aes256`: a building block, not encryption
 by itself. A program that encrypts messages uses `gcm`.

 @see "The block cipher", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_AES_HPP
#define WEBCPP_CRYPTO_CIPHERS_AES_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::crypto::detail {

/**
 * What the AES block cipher stores on a backend whose header does not specialise it: nothing,
 * since its engine refuses the backend where the cipher is called.
 */
template <class Backend, std::size_t KeySize>
struct block_state {};

/**
 * The block cipher's engine on a backend whose header does not specialise it: the family's
 * refusal (`detail/capabilities.hpp`). Its functions are never called: the refusal stops the
 * build where the class is instantiated, and they keep the compiler from adding errors of their
 * own after it; those that return report `backend_failure`, so that a path the refusal missed
 * fails closed.
 */
template <class Backend, std::size_t KeySize>
struct block_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_AES_BLOCK(Backend);

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> init(Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> encrypt(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<void> decrypt(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void move(Arguments&&... /*arguments*/) noexcept {}

    /** Never called. */
    template <class... Arguments>
    static void reset(Arguments&&... /*arguments*/) noexcept {}
};

/**
 * The AES block cipher with keys of `KeySize` bytes on `Backend`, of which `aes128`, `aes192`
 * and `aes256` are the named forms.
 *
 * @tparam KeySize 16, 24 or 32.
 * @tparam Backend A backend tag of `backends`.
 */
template <std::size_t KeySize, class Backend>
class basic_aes {
    using state_type = block_state<Backend, KeySize>;
    using engine = block_engine<Backend, KeySize>;

public:
    /** The backend. */
    using backend_type = Backend;
    /** The family of the capability table, `families::aes_block`, which `supports_v` reads. */
    using family_type = families::aes_block;
    /** The algorithm of the capability table: `tags::aes128`, `tags::aes192` or `tags::aes256`. */
    using name_type =
        std::conditional_t<KeySize == 16, tags::aes128,
                           std::conditional_t<KeySize == 24, tags::aes192, tags::aes256>>;
    /** The key's size in bytes. */
    static constexpr std::size_t key_size = KeySize;
    /** AES's block, 16 bytes. */
    static constexpr std::size_t block_size = 16;

    /**
     * Moves the key schedule; the source is wiped and empty. Moving an empty object gives an
     * empty one: the engine is not asked to move a state it wiped.
     *
     * @param moved_source The source, empty afterwards.
     */
    basic_aes(basic_aes&& moved_source) noexcept
        : keyed_(std::exchange(moved_source.keyed_, false)) {
        if (keyed_) {
            engine::move(state_, moved_source.state_);
        }
    }

    /**
     * Moves the key schedule over this one, which is wiped first.
     *
     * @param moved_source The source, empty afterwards.
     * @return This object.
     */
    basic_aes& operator=(basic_aes&& moved_source) noexcept {
        if (this != &moved_source) {
            engine::reset(state_);
            keyed_ = std::exchange(moved_source.keyed_, false);
            if (keyed_) {
                engine::move(state_, moved_source.state_);
            }
        }
        return *this;
    }

    /** Not copyable: a key schedule has one owner, which wipes it. */
    basic_aes(basic_aes const&) = delete;
    /** Not copyable: a key schedule has one owner, which wipes it. */
    basic_aes& operator=(basic_aes const&) = delete;

    /** Wipes the key schedule. */
    ~basic_aes() { engine::reset(state_); }

    /**
     * Encrypts whole blocks in place.
     *
     * @param block_bytes The data, a multiple of @ref block_size bytes, empty included.
     * @return Nothing; `invalid_state` moved from; `invalid_input_size` for a partial block;
     * the backend's errors.
     */
    [[nodiscard]] boost::system::result<void> encrypt(
        std::span<std::uint8_t> block_bytes) noexcept {
        detail::timing_guard const timing;
        if (!keyed_) {
            return error::invalid_state;
        }
        if (block_bytes.size() % block_size != 0) {
            return error::invalid_input_size;
        }
        return engine::encrypt(state_, block_bytes);
    }

    /**
     * Decrypts whole blocks in place.
     *
     * @param block_bytes The data, a multiple of @ref block_size bytes, empty included.
     * @return Nothing; `invalid_state` moved from; `invalid_input_size` for a partial block;
     * the backend's errors.
     */
    [[nodiscard]] boost::system::result<void> decrypt(
        std::span<std::uint8_t> block_bytes) noexcept {
        detail::timing_guard const timing;
        if (!keyed_) {
            return error::invalid_state;
        }
        if (block_bytes.size() % block_size != 0) {
            return error::invalid_input_size;
        }
        return engine::decrypt(state_, block_bytes);
    }

protected:
    /** An empty object, which `make_as` keys. */
    basic_aes() noexcept = default;

    /**
     * The work of `make`, after which the derived type is the result.
     *
     * @tparam Derived `aes128<Backend>`, `aes192<Backend>` or `aes256<Backend>`.
     * @param key_bytes The key.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    template <class Derived>
    [[nodiscard]] static boost::system::result<Derived> make_as(
        std::span<std::uint8_t const> key_bytes) noexcept {
        if (key_bytes.size() != key_size) {
            return error::invalid_key_size;
        }
        Derived made_object;
        auto const key_result = engine::init(made_object.state_, key_bytes);
        if (!key_result) {
            return key_result.error();
        }
        made_object.keyed_ = true;
        return made_object;
    }

private:
    state_type state_{};
    bool keyed_ = false;
};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::ciphers {

/**
 * AES-128, the block cipher, on a backend that exports it: ctaes, OpenSSL.
 *
 * @tparam Backend The backend; the default is the AEADs' (`default_backend`), which on
 * WebAssembly is BearSSL and has none: name `aes128<backends::ctaes>` there.
 */
template <class Backend = default_backend>
class aes128 : public detail::basic_aes<16, Backend> {
public:
    /**
     * Expands a key.
     *
     * @param key_bytes 16 bytes.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    [[nodiscard]] static boost::system::result<aes128> make(
        std::span<std::uint8_t const> key_bytes) noexcept {
        detail::timing_guard const timing;
        return detail::basic_aes<16, Backend>::template make_as<aes128>(key_bytes);
    }

private:
    friend class detail::basic_aes<16, Backend>;
    aes128() noexcept = default;
};

/**
 * AES-192, the block cipher, on a backend that exports it: ctaes, OpenSSL.
 *
 * @tparam Backend The backend; the default is the AEADs' (`default_backend`), which on
 * WebAssembly is BearSSL and has none: name `aes192<backends::ctaes>` there.
 */
template <class Backend = default_backend>
class aes192 : public detail::basic_aes<24, Backend> {
public:
    /**
     * Expands a key.
     *
     * @param key_bytes 24 bytes.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    [[nodiscard]] static boost::system::result<aes192> make(
        std::span<std::uint8_t const> key_bytes) noexcept {
        detail::timing_guard const timing;
        return detail::basic_aes<24, Backend>::template make_as<aes192>(key_bytes);
    }

private:
    friend class detail::basic_aes<24, Backend>;
    aes192() noexcept = default;
};

/**
 * AES-256, the block cipher, on a backend that exports it: ctaes, OpenSSL.
 *
 * @tparam Backend The backend; the default is the AEADs' (`default_backend`), which on
 * WebAssembly is BearSSL and has none: name `aes256<backends::ctaes>` there.
 */
template <class Backend = default_backend>
class aes256 : public detail::basic_aes<32, Backend> {
public:
    /**
     * Expands a key.
     *
     * @param key_bytes 32 bytes.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    [[nodiscard]] static boost::system::result<aes256> make(
        std::span<std::uint8_t const> key_bytes) noexcept {
        detail::timing_guard const timing;
        return detail::basic_aes<32, Backend>::template make_as<aes256>(key_bytes);
    }

private:
    friend class detail::basic_aes<32, Backend>;
    aes256() noexcept = default;
};

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_AES_HPP
