// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend OpenSSL: OpenSSL 3.5.9 built from `third_party/libs/openssl` by
 `/webcpp/crypto//openssl`, static, on native, wasip2 and wasip3; never on Emscripten. It
 serves `ciphers::aes128/192/256<backends::openssl>` and `ciphers::gcm<...<backends::openssl>>`. Its
 `make` allocates through OpenSSL's own functions. On MSVC, wasip2 and wasip3 OpenSSL is compiled
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

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory_resource>
#include <span>
#include <string_view>
#include <utility>

#ifdef WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE

namespace webcpp::crypto {

/**
 * The resource every allocation of OpenSSL's in the process goes to, from any thread:
 * declared here under `WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE` and defined once by the
 * program. It returns a resource that is never destroyed and is thread-safe whenever
 * OpenSSL may run on two threads at once: OpenSSL frees through it after `main` returns.
 *
 * It must serve OpenSSL's initialisation, which the first use of OpenSSL in the process runs,
 * usually the first `make`: on an OpenSSL built with threads, which MSVC always builds, a
 * resource that fails there makes OpenSSL re-enter its own initialisation, and that call never
 * returns: the process aborts on macOS, deadlocks on Linux and spins on Windows. Only on an
 * OpenSSL built without threads does it return, and every `make` then gives
 * `backend_failure`. On Windows a thread that used OpenSSL keeps its blocks in the resource
 * until the process ends unless it calls `OPENSSL_thread_stop()` before it ends.
 *
 * @return The program's resource.
 * @see "OpenSSL's allocations in your own memory resource", in the guide.
 */
std::pmr::memory_resource& openssl_memory_resource() noexcept;

}  // namespace webcpp::crypto

namespace webcpp::crypto::detail {

/**
 * The alignment of the adapter's blocks, and the size of the header before each that
 * holds its size: at least what the system's `malloc` gives OpenSSL without the option
 * (16 on x86-64 and arm64; on macOS arm64 `alignof(std::max_align_t)` is only 8).
 */
inline constexpr std::size_t openssl_block_alignment =
    (std::max)(alignof(std::max_align_t), std::size_t{__STDCPP_DEFAULT_NEW_ALIGNMENT__});

}  // namespace webcpp::crypto::detail

// The adapter: three C functions given to OpenSSL, with C linkage since OpenSSL calls
// them as C, inline with external linkage so that every file of the program sees one
// function, which the install and make recognise by its address.
extern "C" {

/**
 * OpenSSL's `malloc` under the option: a block of the program's resource, after a header
 * that holds its size.
 *
 * @param size The bytes OpenSSL asks for; 0, or a size whose header overflows, gives null.
 * @return The block, or null, which OpenSSL takes as a failure.
 */
inline void* webcpp_crypto_openssl_malloc(std::size_t size, char const* /*file*/,
                                          int /*line*/) noexcept {
    constexpr std::size_t header = webcpp::crypto::detail::openssl_block_alignment;
    // NOLINTNEXTLINE(readability-redundant-parentheses)
    if (size == 0 || size > (std::numeric_limits<std::size_t>::max)() - header) {
        return nullptr;
    }
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    try {
#endif
        void* const block =
            webcpp::crypto::openssl_memory_resource().allocate(header + size, header);
        if (block == nullptr) {
            return nullptr;
        }
        std::memcpy(block, &size, sizeof size);
        return static_cast<unsigned char*>(block) + header;
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    } catch (...) {  // OpenSSL is C: no exception may cross it
        return nullptr;
    }
#endif
}

/**
 * OpenSSL's `free` under the option: the block back to the program's resource.
 *
 * @param address A block of the adapter's, or null.
 */
inline void webcpp_crypto_openssl_free(void* address, char const* /*file*/, int /*line*/) noexcept {
    if (address == nullptr) {
        return;
    }
    constexpr std::size_t header = webcpp::crypto::detail::openssl_block_alignment;
    auto* const block = static_cast<unsigned char*>(address) - header;
    std::size_t size = 0;
    std::memcpy(&size, block, sizeof size);
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    try {
#endif
        webcpp::crypto::openssl_memory_resource().deallocate(block, header + size, header);
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
        // NOLINTNEXTLINE(bugprone-empty-catch): no exception may cross OpenSSL
    } catch (...) {
    }
#endif
}

/**
 * OpenSSL's `realloc` under the option, as C's: null is `malloc`, 0 frees and gives null,
 * and a failure gives null and leaves the old block valid.
 *
 * @param address The block, or null.
 * @param size The new size.
 * @return The new block, or null.
 */
inline void* webcpp_crypto_openssl_realloc(void* address, std::size_t size, char const* file,
                                           int line) noexcept {
    if (address == nullptr) {
        return webcpp_crypto_openssl_malloc(size, file, line);
    }
    if (size == 0) {
        webcpp_crypto_openssl_free(address, file, line);
        return nullptr;
    }
    void* const moved = webcpp_crypto_openssl_malloc(size, file, line);
    if (moved == nullptr) {
        return nullptr;
    }
    constexpr std::size_t header = webcpp::crypto::detail::openssl_block_alignment;
    std::size_t old = 0;
    std::memcpy(&old, static_cast<unsigned char*>(address) - header, sizeof old);
    std::memcpy(moved, address, (std::min)(old, size));
    webcpp_crypto_openssl_free(address, file, line);
    return moved;
}

}  // extern "C"

namespace webcpp::crypto::detail {

/** Whether OpenSSL's functions are the adapter's: three loads, no call into OpenSSL's heap. */
inline bool openssl_adapter_installed() noexcept {
    CRYPTO_malloc_fn m = nullptr;
    CRYPTO_realloc_fn r = nullptr;
    CRYPTO_free_fn f = nullptr;
    CRYPTO_get_mem_functions(&m, &r, &f);
    return m == &webcpp_crypto_openssl_malloc && r == &webcpp_crypto_openssl_realloc &&
           f == &webcpp_crypto_openssl_free;
}

/**
 * Whether OpenSSL's functions are its own defaults (`mem.c:23-25`): the three addresses
 * are those of `CRYPTO_malloc`, `CRYPTO_realloc` and `CRYPTO_free`. A libcrypto DLL, which
 * webcpp never builds, is refused by this comparison.
 */
inline bool openssl_defaults_installed() noexcept {
    CRYPTO_malloc_fn m = nullptr;
    CRYPTO_realloc_fn r = nullptr;
    CRYPTO_free_fn f = nullptr;
    CRYPTO_get_mem_functions(&m, &r, &f);
    return m == &CRYPTO_malloc && r == &CRYPTO_realloc && f == &CRYPTO_free;
}

}  // namespace webcpp::crypto::detail

#ifdef _MSC_VER
#pragma detect_mismatch("webcpp_crypto_openssl_memory", "resource")
#endif

#elif defined(_MSC_VER)
#pragma detect_mismatch("webcpp_crypto_openssl_memory", "openssl")
#endif  // WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE

namespace webcpp::crypto::detail {

/**
 * The check every OpenSSL `make` runs first, before any call into OpenSSL that allocates:
 * with `WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE`, `memory_functions_not_installed` unless the
 * adapter is installed; without it, nothing.
 *
 * @return Nothing, or `memory_functions_not_installed`.
 */
[[nodiscard]] inline boost::system::result<void> openssl_memory_guard() noexcept {
#ifdef WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE
    if (!openssl_adapter_installed()) {
        return error::memory_functions_not_installed;
    }
#endif
    return {};
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::backends {

// The backend OpenSSL, declared and documented in config.hpp.
struct openssl {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "openssl";

#ifdef WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE
    /**
     * Installs webcpp's adapter as OpenSSL's memory functions, so that every allocation of
     * OpenSSL's in the process goes to `openssl_memory_resource()`. Called as the first
     * statement of `main`, before any thread starts and anything uses OpenSSL. The first use
     * of OpenSSL after it, usually the first `make`, runs OpenSSL's initialisation through the
     * resource, which must not fail there: on an OpenSSL built with threads (MSVC's only
     * build) that call then never returns; on one built without threads every `make` gives
     * `backend_failure` from then on.
     *
     * @return Nothing, also when the adapter is installed already;
     * `memory_functions_refused` when another party installed its own functions, or OpenSSL
     * has allocated with its own and refuses the change.
     */
    [[nodiscard]] static boost::system::result<void> install_memory_functions() noexcept {
        if (detail::openssl_adapter_installed()) {
            return {};
        }
        if (!detail::openssl_defaults_installed()) {
            return error::memory_functions_refused;
        }
        // The resource is constructed here, outside OpenSSL's allocation path.
        static_cast<void>(openssl_memory_resource());
        if (CRYPTO_set_mem_functions(&webcpp_crypto_openssl_malloc, &webcpp_crypto_openssl_realloc,
                                     &webcpp_crypto_openssl_free) != 1) {
            return error::memory_functions_refused;
        }
        return {};
    }
#endif
};

}  // namespace webcpp::crypto::backends

namespace webcpp::crypto::detail {

/** EVP takes lengths as `int`: a span goes in pieces of at most this many bytes, whole blocks. */
inline constexpr std::size_t openssl_piece = static_cast<std::size_t>(INT_MAX) / 16 * 16;

/**
 * OpenSSL's name of AES with keys of `key_length` bytes: GCM, or ECB, the block cipher.
 *
 * @param key_length The key's size: 16, 24 or 32 bytes.
 * @param is_gcm Whether the name is GCM's, else ECB's.
 * @return The name, for `EVP_CIPHER_fetch`.
 */
constexpr char const* openssl_aes_name(std::size_t key_length, bool is_gcm) noexcept {
    if (key_length == 16) {
        return is_gcm ? "AES-128-GCM" : "AES-128-ECB";
    }
    if (key_length == 24) {
        return is_gcm ? "AES-192-GCM" : "AES-192-ECB";
    }
    return is_gcm ? "AES-256-GCM" : "AES-256-ECB";
}

/** OpenSSL's name of AES-GCM with keys of `KeySize` bytes. */
template <std::size_t KeySize>
inline constexpr char const* openssl_gcm_name = openssl_aes_name(KeySize, true);

/** OpenSSL's name of the AES block cipher, ECB without padding, of `KeySize` bytes. */
template <std::size_t KeySize>
inline constexpr char const* openssl_ecb_name = openssl_aes_name(KeySize, false);

/**
 * Keys a context for `cipher_name`, or gives the error of the call that failed:
 * `errc::not_enough_memory` when `EVP_CIPHER_CTX_new` returns null, `backend_failure` when
 * `EVP_CIPHER_fetch` returns null or the key's `EVP_CipherInit_ex` fails. The thread's
 * error queue is left as it was found, through a mark set before the first call that can
 * raise.
 *
 * @param made_context Set to the context, which the caller frees with `EVP_CIPHER_CTX_free`.
 * @param cipher_name OpenSSL's name of the cipher.
 * @param key_bytes The key, of the cipher's size.
 * @param is_encrypting The context's direction.
 * @param use_padding Whether the block cipher pads; GCM ignores it.
 * @return Nothing on success, else the error.
 */
inline boost::system::error_code openssl_context(EVP_CIPHER_CTX*& made_context,
                                                 char const* cipher_name,
                                                 std::span<std::uint8_t const> key_bytes,
                                                 bool is_encrypting, bool use_padding) noexcept {
    if (auto const guard = openssl_memory_guard(); !guard) {
        return guard.error();
    }
    ERR_set_mark();
    EVP_CIPHER* const fetched_cipher = EVP_CIPHER_fetch(nullptr, cipher_name, nullptr);
    if (fetched_cipher == nullptr) {
        ERR_pop_to_mark();
        return error::backend_failure;
    }
    EVP_CIPHER_CTX* const cipher_context = EVP_CIPHER_CTX_new();
    if (cipher_context == nullptr) {
        EVP_CIPHER_free(fetched_cipher);
        ERR_pop_to_mark();
        return boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    }
    // The context holds a reference of its own to the fetched cipher.
    bool const key_result =
        EVP_CipherInit_ex(cipher_context, fetched_cipher, nullptr, key_bytes.data(), nullptr,
                          is_encrypting ? 1 : 0) == 1 &&
        EVP_CIPHER_CTX_set_padding(cipher_context, use_padding ? 1 : 0) == 1;
    EVP_CIPHER_free(fetched_cipher);
    ERR_pop_to_mark();
    if (!key_result) {
        EVP_CIPHER_CTX_free(cipher_context);
        return error::backend_failure;
    }
    made_context = cipher_context;
    return {};
}

/**
 * The error of a call of a message's that OpenSSL's contract says does not fail: the queue
 * is cleared, so that nothing of webcpp's is left for OpenSSL's other users, the caller's
 * earlier entries with it.
 */
inline boost::system::error_code openssl_failed() noexcept {
    ERR_clear_error();
    return error::backend_failure;
}

/**
 * Runs `EVP_CipherUpdate` over `data_bytes` in place, in pieces EVP's `int` can hold.
 *
 * @return Nothing, or `backend_failure`.
 */
[[nodiscard]] inline boost::system::result<void> openssl_update(
    EVP_CIPHER_CTX* cipher_context, std::span<std::uint8_t> data_bytes) noexcept {
    for (std::size_t piece_start = 0; piece_start < data_bytes.size();
         piece_start += openssl_piece) {
        std::size_t const piece_size = (std::min)(openssl_piece, data_bytes.size() - piece_start);
        int written_count = 0;
        if (EVP_CipherUpdate(cipher_context, data_bytes.data() + piece_start, &written_count,
                             data_bytes.data() + piece_start, static_cast<int>(piece_size)) != 1 ||
            std::cmp_not_equal(written_count, piece_size)) {
            return openssl_failed();
        }
    }
    return {};
}

/** GCM's state on OpenSSL: one context, keyed once, its expanded key OpenSSL's. */
template <std::size_t KeySize>
struct gcm_state<backends::openssl, KeySize> {
    /** The context, keyed for GCM; null when the object holds no key. */
    EVP_CIPHER_CTX* context = nullptr;
};

/** GCM's work on OpenSSL. */
template <std::size_t KeySize>
struct gcm_engine<backends::openssl, KeySize> {
    /** The state this engine works on. */
    using state = gcm_state<backends::openssl, KeySize>;

    /** Keys a context for AES-GCM with the key. */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const> key_bytes) noexcept {
        EVP_CIPHER_CTX* made_context = nullptr;
        if (auto const failure_code =
                openssl_context(made_context, openssl_gcm_name<KeySize>, key_bytes, true, true)) {
            return failure_code;
        }
        engine_state.context = made_context;
        return {};
    }

    // Each message re-initialises the context with a null key, which keeps the expanded one,
    // and switches its direction.
    /** Starts a message: its direction, its IV and its additional data. */
    [[nodiscard]] static boost::system::result<void> start(
        state& engine_state, bool is_sealing, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> additional_data_bytes) noexcept {
        int const cipher_direction = is_sealing ? 1 : 0;
        if (EVP_CipherInit_ex(engine_state.context, nullptr, nullptr, nullptr, nullptr,
                              cipher_direction) != 1 ||
            EVP_CIPHER_CTX_ctrl(engine_state.context, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(iv_bytes.size()), nullptr) != 1 ||
            EVP_CipherInit_ex(engine_state.context, nullptr, nullptr, nullptr, iv_bytes.data(),
                              cipher_direction) != 1) {
            return openssl_failed();
        }
        // A null output makes EVP_CipherUpdate take additional data; none is fed as no call.
        for (std::size_t piece_start = 0; piece_start < additional_data_bytes.size();
             piece_start += openssl_piece) {
            std::size_t const piece_size =
                (std::min)(openssl_piece, additional_data_bytes.size() - piece_start);
            int written_count = 0;
            if (EVP_CipherUpdate(engine_state.context, nullptr, &written_count,
                                 additional_data_bytes.data() + piece_start,
                                 static_cast<int>(piece_size)) != 1) {
                return openssl_failed();
            }
        }
        return {};
    }

    /** Encrypts or decrypts a piece of the message in place. */
    [[nodiscard]] static boost::system::result<void> run(
        state& engine_state, std::span<std::uint8_t> data_bytes) noexcept {
        return openssl_update(engine_state.context, data_bytes);
    }

    /** Ends a sealed message and gives its tag. */
    [[nodiscard]] static boost::system::result<void> tag(
        state& engine_state, boost::hash2::digest<16>& output_bytes) noexcept {
        std::array<std::uint8_t, 16> final_block_bytes{};
        int written_count = 0;
        if (EVP_EncryptFinal_ex(engine_state.context, final_block_bytes.data(), &written_count) !=
                1 ||
            EVP_CIPHER_CTX_ctrl(engine_state.context, EVP_CTRL_GCM_GET_TAG, 16,
                                output_bytes.data()) != 1) {
            return openssl_failed();
        }
        return {};
    }

    /** Ends an opened message and checks its tag. */
    [[nodiscard]] static boost::system::result<void> check(
        state& engine_state, std::array<std::uint8_t, 16> const& tag_bytes) noexcept {
        // OpenSSL takes the expected tag through a pointer to mutable bytes, and only reads it.
        std::array<std::uint8_t, 16> expected_tag = tag_bytes;
        if (EVP_CIPHER_CTX_ctrl(engine_state.context, EVP_CTRL_GCM_SET_TAG, 16,
                                expected_tag.data()) != 1) {
            return openssl_failed();
        }
        std::array<std::uint8_t, 16> final_block_bytes{};
        int written_count = 0;
        // With the tag set just above, and the IV given by start, the provider's final
        // (ossl_gcm_stream_final, gcm_cipher_internal) fails only where its comparison of
        // the tags fails: its other refusals, no key, no IV, an IV already finished or no
        // tag, cannot hold in this order of calls. So a failure is the tag's, which raises
        // nothing in the queue.
        if (EVP_DecryptFinal_ex(engine_state.context, final_block_bytes.data(), &written_count) !=
            1) {
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
    // ciphertext and additional data that GHASH's buffer (Xn) may still hold. The calls set
    // no mark of the error queue, since a thread's first ERR_* call allocates its error state
    // and a message allocates nothing. A failure, which OpenSSL does not have for a keyed
    // context, leaves the message until the next start or the reset, and clears the queue as
    // every failure of a message does (openssl_failed).
    /** Ends a message without its tag, leaving nothing of it in the context. */
    static void abandon(state& engine_state) noexcept {
        std::array<std::uint8_t, 12> const zero_iv_bytes{};
        std::array<std::uint8_t, 1> padding_byte{};
        int written_count = 0;
        if (EVP_CipherInit_ex(engine_state.context, nullptr, nullptr, nullptr, nullptr, 1) != 1 ||
            EVP_CIPHER_CTX_ctrl(engine_state.context, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
            EVP_CipherInit_ex(engine_state.context, nullptr, nullptr, nullptr, zero_iv_bytes.data(),
                              1) != 1 ||
            EVP_CipherUpdate(engine_state.context, padding_byte.data(), &written_count,
                             padding_byte.data(), 1) != 1) {
            ERR_clear_error();  // as openssl_failed does for every failure of a message
        }
        // The byte holds a keystream byte of the key's: wiped as key material is.
        wipe(padding_byte.data(), padding_byte.size());
    }

    /** Moves the context, leaving the source empty. */
    static void move(state& target_state, state& source_state) noexcept {
        target_state.context = std::exchange(source_state.context, nullptr);
    }

    // EVP_CIPHER_CTX_free cleanses the expanded key before it frees.
    /** Frees the context. */
    static void reset(state& engine_state) noexcept {
        EVP_CIPHER_CTX_free(std::exchange(engine_state.context, nullptr));
    }
};

/**
 * The block cipher's state on OpenSSL: a context per direction, since a context keyed for
 * encryption keeps the encryption schedule only.
 */
template <std::size_t KeySize>
struct block_state<backends::openssl, KeySize> {
    /** The context keyed for encryption; null when the object holds no key. */
    EVP_CIPHER_CTX* encrypting = nullptr;
    /** The context keyed for decryption; null when the object holds no key. */
    EVP_CIPHER_CTX* decrypting = nullptr;
};

/** The block cipher's work on OpenSSL: ECB without padding over whole blocks. */
template <std::size_t KeySize>
struct block_engine<backends::openssl, KeySize> {
    /** The state this engine works on. */
    using state = block_state<backends::openssl, KeySize>;

    /** Keys a context per direction with the key. */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const> key_bytes) noexcept {
        EVP_CIPHER_CTX* is_encrypting = nullptr;
        if (auto const failure_code =
                openssl_context(is_encrypting, openssl_ecb_name<KeySize>, key_bytes, true, false)) {
            return failure_code;
        }
        EVP_CIPHER_CTX* decrypting_context = nullptr;
        if (auto const failure_code = openssl_context(decrypting_context, openssl_ecb_name<KeySize>,
                                                      key_bytes, false, false)) {
            EVP_CIPHER_CTX_free(is_encrypting);
            return failure_code;
        }
        engine_state.encrypting = is_encrypting;
        engine_state.decrypting = decrypting_context;
        return {};
    }

    /** Encrypts whole blocks in place. */
    [[nodiscard]] static boost::system::result<void> encrypt(
        state& engine_state, std::span<std::uint8_t> block_bytes) noexcept {
        return openssl_update(engine_state.encrypting, block_bytes);
    }

    /** Decrypts whole blocks in place. */
    [[nodiscard]] static boost::system::result<void> decrypt(
        state& engine_state, std::span<std::uint8_t> block_bytes) noexcept {
        return openssl_update(engine_state.decrypting, block_bytes);
    }

    /** Moves both contexts, leaving the source empty. */
    static void move(state& target_state, state& source_state) noexcept {
        target_state.encrypting = std::exchange(source_state.encrypting, nullptr);
        target_state.decrypting = std::exchange(source_state.decrypting, nullptr);
    }

    /** Frees both contexts. */
    static void reset(state& engine_state) noexcept {
        EVP_CIPHER_CTX_free(std::exchange(engine_state.encrypting, nullptr));
        EVP_CIPHER_CTX_free(std::exchange(engine_state.decrypting, nullptr));
    }
};

}  // namespace webcpp::crypto::detail

#endif  // OPENSSL_VERSION_NUMBER
#endif  // WEBCPP_CRYPTO_HAS_OPENSSL
#endif  // WEBCPP_CRYPTO_BACKENDS_OPENSSL_HPP
