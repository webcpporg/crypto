// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend ctaes: Bitcoin Core's constant-time AES, built from its source by
 `/third_party//ctaes`. It serves `ciphers::aes128/192/256<backends::ctaes>`, the block cipher
 alone, on every target.

 @see "The backends", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_CTAES_HPP
#define WEBCPP_CRYPTO_BACKENDS_CTAES_HPP

#include <webcpp/crypto/config.hpp>

#ifndef WEBCPP_CRYPTO_HAS_CTAES
#error \
    "webcpp::crypto: the backend ctaes is used and not linked. In the program's Jamfile, add /third_party//ctaes beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_CTAES=1 and link ctaes.c with webcpp's src/canary_ctaes.c)"
#else

#include <webcpp/crypto/detail/canary.h>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/wipe.hpp>

#include <boost/system/result.hpp>

// ctaes.h declares its functions without extern "C" (Bitcoin Core wraps it
// itself, src/crypto/aes.cpp:9-10).
extern "C" {
#include <ctaes.h>
}

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#ifdef WEBCPP_CRYPTO_CTAES_CANARY_CONFIGURATION
/** The configuration the canary names: a test's, here. */
#define WEBCPP_CRYPTO_DETAIL_CTAES_CONFIGURATION WEBCPP_CRYPTO_CTAES_CANARY_CONFIGURATION
#else
/** The configuration the canary names: ctaes has one, `default`. */
#define WEBCPP_CRYPTO_DETAIL_CTAES_CONFIGURATION default
#endif
/** The canary's name, which every ctaes function of this header reads. */
#define WEBCPP_CRYPTO_DETAIL_CTAES_CANARY                          \
    WEBCPP_CRYPTO_DETAIL_CANARY(ctaes, WEBCPP_CRYPTO_CTAES_COMMIT, \
                                WEBCPP_CRYPTO_DETAIL_CTAES_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                   \
    "webcpp_crypto_backend_ctaes",                                         \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(ctaes, WEBCPP_CRYPTO_CTAES_COMMIT, \
                                        WEBCPP_CRYPTO_DETAIL_CTAES_CONFIGURATION))
#endif

// src/canary_ctaes.c defines the canary with a constant; this is its declaration.
// NOLINTNEXTLINE(bugprone-dynamic-static-initializers): a declaration, never initialised here
extern "C" const char WEBCPP_CRYPTO_DETAIL_CTAES_CANARY;

namespace webcpp::crypto::backends {

/** The backend ctaes. @see "The backends", in the guide. */
struct ctaes {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "ctaes";
};

}  // namespace webcpp::crypto::backends

namespace webcpp::crypto::detail {

/** ctaes's context and functions for a key size. */
template <std::size_t KeySize>
struct ctaes_of;

template <>
struct ctaes_of<16> {
    /** ctaes's AES-128 context, the key schedule. */
    using context = AES128_ctx;

    /** Expands the key into the context. */
    static void init(context* aes_context, unsigned char const* key_bytes) {
        AES128_init(aes_context, key_bytes);
    }

    /** Encrypts `block_count` blocks from `input_blocks` to `output_blocks`. */
    static void encrypt(context const* aes_context, std::size_t block_count,
                        unsigned char* output_blocks, unsigned char const* input_blocks) {
        AES128_encrypt(aes_context, block_count, output_blocks, input_blocks);
    }

    /** Decrypts `block_count` blocks from `input_blocks` to `output_blocks`. */
    static void decrypt(context const* aes_context, std::size_t block_count,
                        unsigned char* output_blocks, unsigned char const* input_blocks) {
        AES128_decrypt(aes_context, block_count, output_blocks, input_blocks);
    }
};

template <>
struct ctaes_of<24> {
    /** ctaes's AES-192 context, the key schedule. */
    using context = AES192_ctx;

    /** Expands the key into the context. */
    static void init(context* aes_context, unsigned char const* key_bytes) {
        AES192_init(aes_context, key_bytes);
    }

    /** Encrypts `block_count` blocks from `input_blocks` to `output_blocks`. */
    static void encrypt(context const* aes_context, std::size_t block_count,
                        unsigned char* output_blocks, unsigned char const* input_blocks) {
        AES192_encrypt(aes_context, block_count, output_blocks, input_blocks);
    }

    /** Decrypts `block_count` blocks from `input_blocks` to `output_blocks`. */
    static void decrypt(context const* aes_context, std::size_t block_count,
                        unsigned char* output_blocks, unsigned char const* input_blocks) {
        AES192_decrypt(aes_context, block_count, output_blocks, input_blocks);
    }
};

template <>
struct ctaes_of<32> {
    /** ctaes's AES-256 context, the key schedule. */
    using context = AES256_ctx;

    /** Expands the key into the context. */
    static void init(context* aes_context, unsigned char const* key_bytes) {
        AES256_init(aes_context, key_bytes);
    }

    /** Encrypts `block_count` blocks from `input_blocks` to `output_blocks`. */
    static void encrypt(context const* aes_context, std::size_t block_count,
                        unsigned char* output_blocks, unsigned char const* input_blocks) {
        AES256_encrypt(aes_context, block_count, output_blocks, input_blocks);
    }

    /** Decrypts `block_count` blocks from `input_blocks` to `output_blocks`. */
    static void decrypt(context const* aes_context, std::size_t block_count,
                        unsigned char* output_blocks, unsigned char const* input_blocks) {
        AES256_decrypt(aes_context, block_count, output_blocks, input_blocks);
    }
};

/** The block cipher's state on ctaes: the key schedule, inside the object. */
template <std::size_t KeySize>
struct block_state<backends::ctaes, KeySize> {
    /** The key schedule. */
    ctaes_of<KeySize>::context schedule;
};

/**
 * The block cipher's work on ctaes, in place: ctaes reads each block into its state before
 * it writes the block out (`ctaes.c`, `AES_encrypt`), so the same pointer is both.
 */
template <std::size_t KeySize>
struct block_engine<backends::ctaes, KeySize> {
    /** The state this engine works on. */
    using state = block_state<backends::ctaes, KeySize>;

    /** Expands the key into the state. */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const> key_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_CTAES_CANARY);
        ctaes_of<KeySize>::init(&engine_state.schedule, key_bytes.data());
        return {};
    }

    /** Encrypts whole blocks in place. */
    [[nodiscard]] static boost::system::result<void> encrypt(
        state& engine_state, std::span<std::uint8_t> block_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_CTAES_CANARY);
        ctaes_of<KeySize>::encrypt(&engine_state.schedule, block_bytes.size() / 16,
                                   block_bytes.data(), block_bytes.data());
        return {};
    }

    /** Decrypts whole blocks in place. */
    [[nodiscard]] static boost::system::result<void> decrypt(
        state& engine_state, std::span<std::uint8_t> block_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_CTAES_CANARY);
        ctaes_of<KeySize>::decrypt(&engine_state.schedule, block_bytes.size() / 16,
                                   block_bytes.data(), block_bytes.data());
        return {};
    }

    /** Copies the schedule and wipes the source. */
    static void move(state& target_state, state& source_state) noexcept {
        target_state = source_state;
        wipe_object(source_state);
    }

    /** Wipes the schedule. */
    static void reset(state& engine_state) noexcept { wipe_object(engine_state); }
};

/** ctaes exports no GCM, and webcpp builds none on another library's AES. */
template <std::size_t KeySize>
struct gcm_state<backends::ctaes, KeySize> {
    static_assert(
        KeySize != 16,
        "webcpp::crypto: ciphers::gcm<ciphers::aes128<backends::ctaes>>: ctaes exports "
        "the AES block cipher alone, and webcpp builds no GCM on another library's AES. "
        "Use a backend that exports GCM: ciphers::gcm<ciphers::aes128<backends::bearssl>> "
        "or ciphers::gcm<ciphers::aes128<backends::openssl>>.");
    static_assert(
        KeySize != 24,
        "webcpp::crypto: ciphers::gcm<ciphers::aes192<backends::ctaes>>: ctaes exports "
        "the AES block cipher alone, and webcpp builds no GCM on another library's AES. "
        "Use a backend that exports GCM: ciphers::gcm<ciphers::aes192<backends::bearssl>> "
        "or ciphers::gcm<ciphers::aes192<backends::openssl>>.");
    static_assert(
        KeySize != 32,
        "webcpp::crypto: ciphers::gcm<ciphers::aes256<backends::ctaes>>: ctaes exports "
        "the AES block cipher alone, and webcpp builds no GCM on another library's AES. "
        "Use a backend that exports GCM: ciphers::gcm<ciphers::aes256<backends::bearssl>> "
        "or ciphers::gcm<ciphers::aes256<backends::openssl>>.");
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_HAS_CTAES
#endif  // WEBCPP_CRYPTO_BACKENDS_CTAES_HPP
