// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend OpenSSL: OpenSSL 3.5.9 built from `third_party/libs/openssl` by
 `/webcpp/crypto//openssl`, static, on native, wasip2 and wasip3; never on Emscripten. It
 serves `aes128/192/256<backends::openssl>` and `gcm<...<backends::openssl>>`. Its `make`
 allocates through OpenSSL's own functions. On MSVC, wasip2 and wasip3 OpenSSL is compiled
 without assembly: table-driven AES and 4-bit GHASH, no AES-NI, not constant time.
 OpenSSL's default initialisation reads the configuration file of the directory it was
 configured with (`/etc/ssl/openssl.cnf`, when the machine has one), as any program of
 OpenSSL does; what it raises meanwhile is popped with the backend's mark.

 The thread's error queue is left as the backend found it, through a mark set before a call
 that can raise and a pop after it, with one exception: a failure of a message's call that
 OpenSSL's contract says does not fail clears the queue, the caller's entries with it
 (`openssl_failed`). The queue is a ring of 16 slots (`ERR_NUM_ERRORS`), which holds 15
 entries: when the caller's entries and those OpenSSL raises between the mark and the pop are
 more than 15, the oldest are overwritten, the marked one among them, and the pop then empties
 the queue, the caller's entries with it. A caller that keeps entries across a call of the
 backend keeps few.

 @see "The backends", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_OPENSSL_HPP
#define WEBCPP_CRYPTO_BACKENDS_OPENSSL_HPP

#include <webcpp/crypto/config.hpp>

#ifndef WEBCPP_CRYPTO_HAS_OPENSSL
#error \
    "webcpp::crypto: the backend OpenSSL is used and not linked. In the program's Jamfile, add /webcpp/crypto//openssl beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto)"
#else

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error \
    "webcpp::crypto: the backend OpenSSL needs OpenSSL 3.0 or later, and the headers found are of an older OpenSSL. In the program's Jamfile, name /webcpp/crypto//openssl, which builds OpenSSL 3.5.9. (without b2: put OpenSSL 3's include/ first)"
#else

#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace webcpp::crypto::backends {

// The backend OpenSSL, declared and documented in config.hpp (spec section 3.3).
struct openssl {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "openssl";
};

}  // namespace webcpp::crypto::backends

namespace webcpp::crypto::detail {

/** EVP takes lengths as `int`: a span goes in pieces of at most this many bytes, whole blocks. */
inline constexpr std::size_t openssl_piece = static_cast<std::size_t>(INT_MAX) / 16 * 16;

/**
 * OpenSSL's name of AES with keys of `key_size` bytes: GCM, or ECB, the block cipher.
 *
 * @param key_size The key's size: 16, 24 or 32 bytes.
 * @param gcm Whether the name is GCM's, else ECB's.
 * @return The name, for `EVP_CIPHER_fetch`.
 */
constexpr char const* openssl_aes_name(std::size_t key_size, bool gcm) noexcept {
    if (key_size == 16) {
        return gcm ? "AES-128-GCM" : "AES-128-ECB";
    }
    if (key_size == 24) {
        return gcm ? "AES-192-GCM" : "AES-192-ECB";
    }
    return gcm ? "AES-256-GCM" : "AES-256-ECB";
}

/** OpenSSL's name of AES-GCM with keys of `KeySize` bytes. */
template <std::size_t KeySize>
inline constexpr char const* openssl_gcm_name = openssl_aes_name(KeySize, true);

/** OpenSSL's name of the AES block cipher, ECB without padding, of `KeySize` bytes. */
template <std::size_t KeySize>
inline constexpr char const* openssl_ecb_name = openssl_aes_name(KeySize, false);

/**
 * Keys a context for `cipher`, or gives the error of the call that failed (spec section 3.3):
 * `errc::not_enough_memory` when `EVP_CIPHER_CTX_new` returns null, `backend_failure` when
 * `EVP_CIPHER_fetch` returns null or the key's `EVP_CipherInit_ex` fails. The thread's
 * error queue is left as it was found, through a mark set before the first call that can
 * raise.
 *
 * @param made Set to the context, which the caller frees with `EVP_CIPHER_CTX_free`.
 * @param cipher OpenSSL's name of the cipher.
 * @param key The key, of the cipher's size.
 * @param encrypting The context's direction.
 * @param padding Whether the block cipher pads; GCM ignores it.
 * @return Nothing on success, else the error.
 */
inline boost::system::error_code openssl_context(EVP_CIPHER_CTX*& made, char const* cipher,
                                                 std::span<std::uint8_t const> key, bool encrypting,
                                                 bool padding) noexcept {
    ERR_set_mark();
    EVP_CIPHER* const fetched = EVP_CIPHER_fetch(nullptr, cipher, nullptr);
    if (fetched == nullptr) {
        ERR_pop_to_mark();
        return error::backend_failure;
    }
    EVP_CIPHER_CTX* const context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        EVP_CIPHER_free(fetched);
        ERR_pop_to_mark();
        return boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    }
    // The context holds a reference of its own to the fetched cipher.
    bool const keyed = EVP_CipherInit_ex(context, fetched, nullptr, key.data(), nullptr,
                                         encrypting ? 1 : 0) == 1 &&
                       EVP_CIPHER_CTX_set_padding(context, padding ? 1 : 0) == 1;
    EVP_CIPHER_free(fetched);
    ERR_pop_to_mark();
    if (!keyed) {
        EVP_CIPHER_CTX_free(context);
        return error::backend_failure;
    }
    made = context;
    return {};
}

/**
 * The error of a call of a message's that OpenSSL's contract says does not fail: the queue
 * is cleared, so that nothing of webcpp's is left for OpenSSL's other users, the caller's
 * earlier entries with it (spec section 3.3).
 */
inline boost::system::error_code openssl_failed() noexcept {
    ERR_clear_error();
    return error::backend_failure;
}

/**
 * Runs `EVP_CipherUpdate` over `data` in place, in pieces EVP's `int` can hold.
 *
 * @return Nothing, or `backend_failure`.
 */
inline boost::system::result<void> openssl_update(EVP_CIPHER_CTX* context,
                                                  std::span<std::uint8_t> data) noexcept {
    for (std::size_t at = 0; at < data.size(); at += openssl_piece) {
        std::size_t const piece = (std::min)(openssl_piece, data.size() - at);
        int written = 0;
        if (EVP_CipherUpdate(context, data.data() + at, &written, data.data() + at,
                             static_cast<int>(piece)) != 1 ||
            std::cmp_not_equal(written, piece)) {
            return openssl_failed();
        }
    }
    return {};
}

/** GCM's state on OpenSSL: one context, keyed once, its expanded key OpenSSL's. */
template <std::size_t KeySize>
struct gcm_state<backends::openssl, KeySize> {
    EVP_CIPHER_CTX* context = nullptr;
};

/** GCM's work on OpenSSL. */
template <std::size_t KeySize>
struct gcm_engine<backends::openssl, KeySize> {
    using state = gcm_state<backends::openssl, KeySize>;

    static boost::system::result<void> init(state& s, std::span<std::uint8_t const> key) noexcept {
        EVP_CIPHER_CTX* made = nullptr;
        if (auto const failed = openssl_context(made, openssl_gcm_name<KeySize>, key, true, true)) {
            return failed;
        }
        s.context = made;
        return {};
    }

    // Each message re-initialises the context with a null key, which keeps the expanded one,
    // and switches its direction (CR-PROBES ossl_open.c: "good open: ok=1").
    static boost::system::result<void> start(
        state& s, bool sealing, std::span<std::uint8_t const> iv,
        std::span<std::uint8_t const> additional_data) noexcept {
        int const direction = sealing ? 1 : 0;
        if (EVP_CipherInit_ex(s.context, nullptr, nullptr, nullptr, nullptr, direction) != 1 ||
            EVP_CIPHER_CTX_ctrl(s.context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()),
                                nullptr) != 1 ||
            EVP_CipherInit_ex(s.context, nullptr, nullptr, nullptr, iv.data(), direction) != 1) {
            return openssl_failed();
        }
        // A null output makes EVP_CipherUpdate take additional data; none is fed as no call.
        for (std::size_t at = 0; at < additional_data.size(); at += openssl_piece) {
            std::size_t const piece = (std::min)(openssl_piece, additional_data.size() - at);
            int written = 0;
            if (EVP_CipherUpdate(s.context, nullptr, &written, additional_data.data() + at,
                                 static_cast<int>(piece)) != 1) {
                return openssl_failed();
            }
        }
        return {};
    }

    static boost::system::result<void> run(state& s, std::span<std::uint8_t> data) noexcept {
        return openssl_update(s.context, data);
    }

    static boost::system::result<void> tag(state& s, boost::hash2::digest<16>& out) noexcept {
        std::array<std::uint8_t, 16> final_block{};
        int written = 0;
        if (EVP_EncryptFinal_ex(s.context, final_block.data(), &written) != 1 ||
            EVP_CIPHER_CTX_ctrl(s.context, EVP_CTRL_GCM_GET_TAG, 16, out.data()) != 1) {
            return openssl_failed();
        }
        return {};
    }

    static boost::system::result<void> check(state& s,
                                             std::array<std::uint8_t, 16> const& tag) noexcept {
        // OpenSSL takes the expected tag through a pointer to mutable bytes, and only reads it.
        std::array<std::uint8_t, 16> expected = tag;
        if (EVP_CIPHER_CTX_ctrl(s.context, EVP_CTRL_GCM_SET_TAG, 16, expected.data()) != 1) {
            return openssl_failed();
        }
        std::array<std::uint8_t, 16> final_block{};
        int written = 0;
        // With the tag set just above, and the IV given by start, the provider's final
        // (ossl_gcm_stream_final, gcm_cipher_internal) fails only where its comparison of
        // the tags fails: its other refusals, no key, no IV, an IV already finished or no
        // tag, cannot hold in this order of calls. So a failure is the tag's, which raises
        // nothing in the queue (CR-PROBES ossl_open.out).
        if (EVP_DecryptFinal_ex(s.context, final_block.data(), &written) != 1) {
            return error::authentication_failed;
        }
        return {};
    }

    // Ends the message by starting another in its place, with the zero IV of 12 bytes, and
    // sealing one zero byte of it. The provider keeps an IV given to EVP_CipherInit_ex until
    // the next update, where CRYPTO_gcm128_setiv zeroes the lengths and the GHASH value (Xi)
    // and derives the counter blocks (Yi, EK0) from it; the byte sealed then replaces the
    // last keystream block (EKi), the one other value of the abandoned message. What the
    // context holds after it is derived from the key and the zero IV alone, or is public:
    // ciphertext and additional data that GHASH's buffer (Xn) may still hold. A failure,
    // which OpenSSL does not have for a keyed context, leaves the message until the next
    // start or the reset; what it raises is popped with the mark.
    static void abandon(state& s) noexcept {
        std::array<std::uint8_t, 12> const zero_iv{};
        std::array<std::uint8_t, 1> byte{};
        int written = 0;
        ERR_set_mark();
        static_cast<void>(
            EVP_CipherInit_ex(s.context, nullptr, nullptr, nullptr, nullptr, 1) == 1 &&
            EVP_CIPHER_CTX_ctrl(s.context, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_CipherInit_ex(s.context, nullptr, nullptr, nullptr, zero_iv.data(), 1) == 1 &&
            EVP_CipherUpdate(s.context, byte.data(), &written, byte.data(), 1) == 1);
        ERR_pop_to_mark();
        // The byte holds a keystream byte of the key's: wiped as key material is.
        wipe(byte.data(), byte.size());
    }

    static void move(state& to, state& from) noexcept {
        to.context = std::exchange(from.context, nullptr);
    }

    // EVP_CIPHER_CTX_free cleanses the expanded key before it frees.
    static void reset(state& s) noexcept { EVP_CIPHER_CTX_free(std::exchange(s.context, nullptr)); }
};

/**
 * The block cipher's state on OpenSSL: a context per direction, since a context keyed for
 * encryption keeps the encryption schedule only.
 */
template <std::size_t KeySize>
struct block_state<backends::openssl, KeySize> {
    EVP_CIPHER_CTX* encrypting = nullptr;
    EVP_CIPHER_CTX* decrypting = nullptr;
};

/** The block cipher's work on OpenSSL: ECB without padding over whole blocks. */
template <std::size_t KeySize>
struct block_engine<backends::openssl, KeySize> {
    using state = block_state<backends::openssl, KeySize>;

    static boost::system::result<void> init(state& s, std::span<std::uint8_t const> key) noexcept {
        EVP_CIPHER_CTX* encrypting = nullptr;
        if (auto const failed =
                openssl_context(encrypting, openssl_ecb_name<KeySize>, key, true, false)) {
            return failed;
        }
        EVP_CIPHER_CTX* decrypting = nullptr;
        if (auto const failed =
                openssl_context(decrypting, openssl_ecb_name<KeySize>, key, false, false)) {
            EVP_CIPHER_CTX_free(encrypting);
            return failed;
        }
        s.encrypting = encrypting;
        s.decrypting = decrypting;
        return {};
    }

    static boost::system::result<void> encrypt(state& s, std::span<std::uint8_t> blocks) noexcept {
        return openssl_update(s.encrypting, blocks);
    }

    static boost::system::result<void> decrypt(state& s, std::span<std::uint8_t> blocks) noexcept {
        return openssl_update(s.decrypting, blocks);
    }

    static void move(state& to, state& from) noexcept {
        to.encrypting = std::exchange(from.encrypting, nullptr);
        to.decrypting = std::exchange(from.decrypting, nullptr);
    }

    static void reset(state& s) noexcept {
        EVP_CIPHER_CTX_free(std::exchange(s.encrypting, nullptr));
        EVP_CIPHER_CTX_free(std::exchange(s.decrypting, nullptr));
    }
};

}  // namespace webcpp::crypto::detail

#endif  // OPENSSL_VERSION_NUMBER
#endif  // WEBCPP_CRYPTO_HAS_OPENSSL
#endif  // WEBCPP_CRYPTO_BACKENDS_OPENSSL_HPP
