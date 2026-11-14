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
#ifndef WEBCPP_CRYPTO_AES_HPP
#define WEBCPP_CRYPTO_AES_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto {

namespace detail {

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
    /** The key's size in bytes. */
    static constexpr std::size_t key_size = KeySize;
    /** AES's block, 16 bytes. */
    static constexpr std::size_t block_size = 16;

    /**
     * Moves the key schedule; the source is wiped and empty. Moving an empty object gives an
     * empty one: the engine is not asked to move a state it wiped (I1).
     *
     * @param other The source, empty afterwards.
     */
    basic_aes(basic_aes&& other) noexcept : keyed_(std::exchange(other.keyed_, false)) {
        if (keyed_) {
            engine::move(state_, other.state_);
        }
    }

    /**
     * Moves the key schedule over this one, which is wiped first.
     *
     * @param other The source, empty afterwards.
     * @return This object.
     */
    basic_aes& operator=(basic_aes&& other) noexcept {
        if (this != &other) {
            engine::reset(state_);
            keyed_ = std::exchange(other.keyed_, false);
            if (keyed_) {
                engine::move(state_, other.state_);
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
     * @param blocks The data, a multiple of @ref block_size bytes, empty included.
     * @return Nothing; `invalid_state` moved from; `invalid_input_size` for a partial block;
     * the backend's errors.
     */
    boost::system::result<void> encrypt(std::span<std::uint8_t> blocks) noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (blocks.size() % block_size != 0) {
            return error::invalid_input_size;
        }
        return engine::encrypt(state_, blocks);
    }

    /**
     * Decrypts whole blocks in place.
     *
     * @param blocks The data, a multiple of @ref block_size bytes, empty included.
     * @return Nothing; `invalid_state` moved from; `invalid_input_size` for a partial block;
     * the backend's errors.
     */
    boost::system::result<void> decrypt(std::span<std::uint8_t> blocks) noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        if (blocks.size() % block_size != 0) {
            return error::invalid_input_size;
        }
        return engine::decrypt(state_, blocks);
    }

protected:
    /** An empty object, which `make_as` keys. */
    basic_aes() noexcept = default;

    /**
     * The work of `make`, after which the derived type is the result.
     *
     * @tparam Derived `aes128<Backend>`, `aes192<Backend>` or `aes256<Backend>`.
     * @param key The key.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    template <class Derived>
    static boost::system::result<Derived> make_as(std::span<std::uint8_t const> key) noexcept {
        if (key.size() != key_size) {
            return error::invalid_key_size;
        }
        Derived made;
        auto const keyed = engine::init(made.state_, key);
        if (!keyed) {
            return keyed.error();
        }
        made.keyed_ = true;
        return made;
    }

private:
    state_type state_{};
    bool keyed_ = false;
};

}  // namespace detail

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
     * @param key 16 bytes.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    static boost::system::result<aes128> make(std::span<std::uint8_t const> key) noexcept {
        return detail::basic_aes<16, Backend>::template make_as<aes128>(key);
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
     * @param key 24 bytes.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    static boost::system::result<aes192> make(std::span<std::uint8_t const> key) noexcept {
        return detail::basic_aes<24, Backend>::template make_as<aes192>(key);
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
     * @param key 32 bytes.
     * @return The cipher; `invalid_key_size`; the backend's errors.
     */
    static boost::system::result<aes256> make(std::span<std::uint8_t const> key) noexcept {
        return detail::basic_aes<32, Backend>::template make_as<aes256>(key);
    }

private:
    friend class detail::basic_aes<32, Backend>;
    aes256() noexcept = default;
};

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_AES_HPP
