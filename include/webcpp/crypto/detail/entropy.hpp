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
// The test seam of spec section 8.4: a test defines the source, which returns 0, or -1 with
// errno set, as getentropy does (lint-world: the call it stands in for, named, not made).
extern "C" int webcpp_test_entropy(void* out, std::size_t size);
#elif !defined(_WIN32)
#include <sys/random.h>  // lint-world: getentropy, the system's entropy, this header's purpose
#endif

namespace webcpp::crypto::detail {

/** The most one call of the system's source gives (POSIX.1-2024's `GETENTROPY_MAX`). */
inline constexpr std::size_t entropy_piece = 256;

/**
 * Asks the platform's one source for `size` bytes, at most @ref entropy_piece.
 *
 * Linux, macOS and WASI: the POSIX entropy call, which fills the buffer or fails with `errno`
 * set (POSIX.1-2024; wasmtime serves it with the host's generator). Emscripten: the same call
 * becomes `crypto.getRandomValues` in the browser and in node, and fails with `ENOTSUP` in an
 * audio worklet, which has no `crypto` (Emscripten's `src/lib/libwasi.js`). Windows:
 * `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, the system's generator
 * (learn.microsoft.com, `BCryptGenRandom`).
 *
 * @param out Where to write.
 * @param size How many bytes, 1 to @ref entropy_piece.
 * @return Nothing, `errc::not_supported` where there is no generator, or
 * `error::entropy_unavailable`.
 */
inline boost::system::result<void> read_entropy(std::uint8_t* out, std::size_t size) noexcept {
#if defined(_WIN32) && !defined(WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY)
    NTSTATUS const status =
        ::BCryptGenRandom(nullptr, out, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    int const failed = BCRYPT_SUCCESS(status) ? 0 : EIO;
#else
#ifdef WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY
    int const called = webcpp_test_entropy(out, size);
#else
    int const called = ::getentropy(out, size);  // lint-world: the entropy
#endif
    // A failed call that leaves errno 0 is still a failure: never report it as a filled piece.
    int const failed = called == 0 ? 0 : (errno != 0 ? errno : EIO);
#endif
    if (failed == ENOTSUP) {
        return boost::system::errc::make_error_code(boost::system::errc::not_supported);
    }
    if (failed != 0) {
        return error::entropy_unavailable;
    }
    return {};
}

/**
 * Fills `out` from the platform's source, in pieces of at most @ref entropy_piece bytes.
 *
 * No generator of webcpp's or of a backend's stands between the source and `out`, and no
 * weaker source is ever tried: when the source fails, `out` is zeroed whole, so that nothing
 * the caller may use is left in it.
 *
 * @param out The bytes to fill.
 * @return Nothing, or the source's error.
 */
inline boost::system::result<void> fill_from_system(std::span<std::uint8_t> out) noexcept {
    for (std::size_t done = 0; done < out.size(); done += entropy_piece) {
        std::size_t const piece = (std::min)(out.size() - done, entropy_piece);
        auto const read = read_entropy(out.data() + done, piece);
        if (!read) {
            wipe(out.data(), out.size());
            return read.error();
        }
    }
    return {};
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_ENTROPY_HPP
