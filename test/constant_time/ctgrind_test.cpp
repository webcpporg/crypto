// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Under Valgrind's memcheck, the keys, the seeds, the plaintext, the block and the tag are marked
// undefined: a branch or a memory index that depends on them is an error, and the run fails
// (--error-exitcode). The paths are paths.hpp's, shared with msan_test.cpp, and two of this
// checker alone: from_key, seal and open of BearSSL's AES-GCM, where the planted leak is, and
// from_key and seal of OpenSSL's AES-GCM and ChaCha20-Poly1305. Each path's output is checked to be
// undefined too, the planted leak's path aside: the mark reaches it, so the path is traced.

#include "paths.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <valgrind/memcheck.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>

namespace {

namespace crypto = webcpp::crypto;
using webcpp::test::constant_time::carries_mark;
using webcpp::test::constant_time::check;

/** memcheck's primitives for paths.hpp. */
struct memcheck {
    /** memcheck follows a subtraction's carry. */
    static constexpr bool exact_subtraction = true;
    /** A destroyed object's bytes keep their definedness. */
    static constexpr bool reads_destroyed = true;

    /** Marks bytes secret: memcheck's undefined. */
    static void mark_secret(std::span<std::uint8_t> bytes) {
        VALGRIND_MAKE_MEM_UNDEFINED(bytes.data(), bytes.size());
    }

    /** Marks bytes public: defined. */
    static void mark_public(std::span<std::uint8_t const> bytes) {
        VALGRIND_MAKE_MEM_DEFINED(bytes.data(), bytes.size());
    }

    /**
     * Whether memcheck holds some bit of the first 64 of `bytes` undefined, read from its own
     * shadow without an error; empty when memcheck cannot read it (not under Valgrind, or the
     * bytes are not addressable).
     */
    static std::optional<bool> traced(std::span<std::uint8_t const> bytes) {
        std::array<std::uint8_t, 64> bits{};
        std::size_t const size = (std::min)(bytes.size(), bits.size());
        if (VALGRIND_GET_VBITS(bytes.data(), bits.data(), size) != 1) {
            return std::nullopt;
        }
        return std::any_of(bits.begin(), bits.begin() + static_cast<std::ptrdiff_t>(size),
                           [](std::uint8_t bit) { return bit != 0; });
    }

    /** Reports the verdict when it is undefined. */
    static void verdict(bool const& value) {
        static_cast<void>(VALGRIND_CHECK_VALUE_IS_DEFINED(value));
    }
};

/**
 * from_key, seal and open of BearSSL with the key, the data and the tag secret.
 */
int bearssl_seal_and_open() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    VALGRIND_MAKE_MEM_UNDEFINED(key.data(), key.size());
    VALGRIND_MAKE_MEM_UNDEFINED(data.data(), data.size());
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
    // The planted leak: a branch on a secret byte, which memcheck must report.
    if (key[0] == 0x42) {
        std::printf("planted\n");
    }
#endif
    auto made =
        crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::from_key(key);
    auto tag = made->seal(iv, {}, data);
    VALGRIND_MAKE_MEM_UNDEFINED(tag->data(), tag->size());
    // The verdict is declassified inside the engine (WEBCPP_CRYPTO_DETAIL_DECLASSIFY).
    auto const opened = made->open(iv, {}, data, *tag);
    // And only because of that mark is the verdict defined: checked, since an optimiser may
    // turn the engine's branch on it into a select, which memcheck does not report.
    bool const verdict = opened.has_value();
    memcheck::verdict(verdict);
    return verdict ? 0 : 1;
}

/**
 * from_key and seal of OpenSSL with the key and the data secret. Its open is not checked with
 * secrets: OpenSSL branches on the tag's verdict inside EVP_DecryptFinal_ex, where webcpp
 * cannot declassify it; the documentation says so.
 */
template <class Aead>
int openssl_seal(char const* what) {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    memcheck::mark_secret(key);
    memcheck::mark_secret(data);
    auto made = Aead::from_key(key);
    auto const tag = made->seal(iv, {}, data);
    return check(tag.has_value() && carries_mark<memcheck>(data), what);
}

}  // namespace

int main() {
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_SCALAR_CHECK
    // The planted early exit in a copy of P-256's scalar check (paths.hpp), first: memcheck
    // must report it there, in that copy (valgrind.mjs --in), whatever the paths after it do.
    static_cast<void>(webcpp::test::constant_time::planted_scalar_check<memcheck>());
#endif
    namespace ciphers = crypto::ciphers;
    int const failures =
        webcpp::test::constant_time::common_paths<memcheck>() + bearssl_seal_and_open() +
        openssl_seal<ciphers::gcm<ciphers::aes256<crypto::backends::openssl>>>("OpenSSL GCM") +
        openssl_seal<ciphers::chacha20_poly1305<crypto::backends::openssl>>("OpenSSL ChaCha");
    std::printf("constant time under memcheck: %s\n", failures == 0 ? "ok" : "FAILED");
    return failures;
}
