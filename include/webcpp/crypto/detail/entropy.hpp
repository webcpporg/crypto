// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_ENTROPY_HPP
#define WEBCPP_CRYPTO_DETAIL_ENTROPY_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/windows.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>

#ifdef WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY
// The test seam: a test defines the source, which returns 0, or -1 with
// errno set, as getentropy does (lint-world: the call it stands in for, named, not made).
extern "C" int webcpp_test_entropy(void* output_bytes, std::size_t byte_count);
#elif defined(__EMSCRIPTEN__)
#include <emscripten/em_asm.h>
#elif !defined(_WIN32)
#include <sys/random.h>  // lint-world: getentropy, the system's entropy, this header's purpose
#endif

namespace webcpp::crypto::detail {

/** The most one call of the system's source gives (POSIX.1-2024's `GETENTROPY_MAX`). */
inline constexpr std::size_t entropy_piece = 256;

/**
 * Asks the platform's one source for `byte_count` bytes, at most @ref entropy_piece.
 *
 * Linux, macOS and WASI: the POSIX entropy call, which fills the buffer or fails with `errno`
 * set (POSIX.1-2024; wasmtime serves it with the host's generator). Emscripten:
 * `crypto.getRandomValues`, in the browser and in node, called here and not through
 * Emscripten's own entropy call: that one (`random_get` in `src/lib/libwasi.js`) lets an
 * exception thrown by `crypto.getRandomValues`, or by node's `randomFillSync`, unwind through
 * WebAssembly, which terminates the program. Here a throw is caught in JavaScript and becomes
 * `error::entropy_unavailable`, and a missing `crypto.getRandomValues` (an audio worklet's
 * case) `errc::not_supported`. The draw goes into a fresh array, then is copied into the
 * module's memory, since `getRandomValues` refuses a view of shared memory (W3C WebCryptoAPI).
 * It is an `EM_ASM_INT` in this inline function, whose code string is one merged definition
 * across translation units: an `EM_JS` defines external symbols in every translation unit that
 * includes it, and a program of two such units would not link. Windows: `BCryptGenRandom` with
 * `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, the system's generator (learn.microsoft.com,
 * `BCryptGenRandom`).
 *
 * @param output_bytes Where to write.
 * @param byte_count How many bytes, 1 to @ref entropy_piece.
 * @return Nothing, `errc::not_supported` where there is no generator, or
 * `error::entropy_unavailable`.
 */
[[nodiscard]] inline boost::system::result<void> read_entropy(std::uint8_t* output_bytes,
                                                              std::size_t byte_count) noexcept {
#if defined(_WIN32) && !defined(WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY)
    NTSTATUS const status_code = ::BCryptGenRandom(  // lint-world: the entropy, on Windows
        nullptr, output_bytes, static_cast<ULONG>(byte_count), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    int const failure_code = BCRYPT_SUCCESS(status_code) ? 0 : EIO;
#elif defined(__EMSCRIPTEN__) && !defined(WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY)
    // 0: filled; 1: no crypto.getRandomValues (an audio worklet); 2: it threw. The code is a
    // string with its newlines gone: a comment inside it ends only with its closing mark. It is
    // JavaScript, which clang-format would break (`!==` into `! ==`).
    // clang-format off
    int const draw_status = EM_ASM_INT({
        const source = globalThis.crypto;
        if (!source || typeof source.getRandomValues !== 'function') return 1;
        try {
            /* a fresh buffer: never a view of shared memory */
            const drawn = new Uint8Array($1);
            source.getRandomValues(drawn);
            HEAPU8.set(drawn, $0);
            return 0;
        } catch (error) {
            return 2;
        }
    }, output_bytes, static_cast<int>(byte_count));
    // clang-format on
    int const failure_code = draw_status == 0 ? 0 : (draw_status == 1 ? ENOTSUP : EIO);
#else
#ifdef WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY
    int const call_result =
        webcpp_test_entropy(output_bytes, byte_count);  // lint-world: a test's planted entropy
#else
    int const call_result = ::getentropy(output_bytes, byte_count);  // lint-world: the entropy
#endif
    // A failed call that leaves errno 0 is still a failure: never report it as a filled piece.
    int const failure_code = call_result == 0 ? 0 : (errno != 0 ? errno : EIO);
#endif
    if (failure_code == ENOTSUP) {
        return boost::system::errc::make_error_code(boost::system::errc::not_supported);
    }
    if (failure_code != 0) {
        return error::entropy_unavailable;
    }
    return {};
}

/**
 * Fills `output_bytes` from the platform's source, in pieces of at most @ref entropy_piece bytes.
 *
 * No generator of webcpp's or of a backend's stands between the source and `output_bytes`, and no
 * weaker source is ever tried: when the source fails, `output_bytes` is zeroed whole, so that
 * nothing the caller may use is left in it.
 *
 * @param output_bytes The bytes to fill.
 * @return Nothing, or the source's error.
 */
[[nodiscard]] inline boost::system::result<void> fill_from_system(
    std::span<std::uint8_t> output_bytes) noexcept {
    for (std::size_t filled_count = 0; filled_count < output_bytes.size();
         filled_count += entropy_piece) {
        std::size_t const piece_size =
            (std::min)(output_bytes.size() - filled_count, entropy_piece);
        auto const read_result = read_entropy(output_bytes.data() + filled_count, piece_size);
        if (!read_result) {
            wipe(output_bytes.data(), output_bytes.size());
            return read_result.error();
        }
    }
    return {};
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_ENTROPY_HPP
