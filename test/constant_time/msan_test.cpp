// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// MemorySanitizer's poisoning (spec section 8.3): the keys, the seeds, the plaintext, the block
// and the tag are poisoned, and a branch or an index that depends on them, in webcpp's code,
// BearSSL's, ctaes's or libsodium's, all instrumented, ends the run with a report. The paths are
// paths.hpp's, shared with ctgrind_test.cpp, and BearSSL's AES-GCM, where the planted leak is;
// OpenSSL is not built instrumented, so its paths are memcheck's alone. Each path's output is
// checked to be poisoned too, where MemorySanitizer's shadow keeps it: the poison reaches it, so
// the path is traced.
//
// MemorySanitizer approximates a subtraction's shadow by its operands' without the carry, so the
// constant-time reduction to one bit, ((x - 1) >> 8) & 1 or ~(q | -q) >> 31, of a value whose low
// bits are poisoned comes out initialised (measured with clang 18, 2026-11-18). Every verdict
// here is computed that way, BearSSL's, libsodium's and is_all_zero's: MemorySanitizer reports
// no branch on one with or without its mark (a mutant without webcpp's marks passes), and
// memcheck, which propagates the carry, is the check of the marks. For the same reason
// is_all_zero's result and X25519's public key (ref10's table lookup selects public points with
// masks of that form) are not checked poisoned here, and ctgrind_test.cpp checks them traced.

#include "paths.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <sanitizer/msan_interface.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>

namespace {

namespace crypto = webcpp::crypto;
using webcpp::test::constant_time::check;

/** MemorySanitizer's primitives for paths.hpp. */
struct memory_sanitizer {
    /** A subtraction's shadow drops the carry (the file's head comment). */
    static constexpr bool exact_subtraction = false;
    /**
     * A destroyed object is poisoned by MemorySanitizer itself (-fsanitize-memory-use-after-dtor,
     * on by default): the destructor's wipe is run for its branches only, and
     * ctgrind_test.cpp checks its bytes.
     */
    static constexpr bool reads_destroyed = false;

    /** Poisons bytes: they are secret. */
    static void mark_secret(std::span<std::uint8_t> bytes) {
        __msan_poison(bytes.data(), bytes.size());
    }

    /** Unpoisons bytes: they are public. */
    static void mark_public(std::span<std::uint8_t const> bytes) {
        __msan_unpoison(bytes.data(), bytes.size());
    }

    /** Whether some byte of `bytes` is poisoned; MemorySanitizer always reads its shadow. */
    static std::optional<bool> traced(std::span<std::uint8_t const> bytes) {
        return __msan_test_shadow(bytes.data(), bytes.size()) != -1;
    }

    /** Reports the verdict when it is poisoned. */
    static void verdict(bool const& value) {
        __msan_check_mem_is_initialized(&value, sizeof value);
    }
};

/**
 * make, seal and open of BearSSL's AES-GCM with the key, the data and the tag poisoned. The
 * planted leak, a branch on a key byte, is here.
 */
int bearssl_gcm() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    __msan_poison(key.data(), key.size());
    __msan_poison(data.data(), data.size());
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
    if (key[0] == 0) {  // the planted leak: MemorySanitizer must report it
        std::printf("planted\n");
    }
#endif
    auto made = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::make(key);
    auto tag = made->seal(iv, {}, data);
    __msan_poison(tag->data(), tag->size());
    // The verdict is declassified inside the engine (WEBCPP_CRYPTO_DETAIL_DECLASSIFY).
    auto const opened = made->open(iv, {}, data, *tag);
    // And the verdict is checked initialised here, the twin of ctgrind_test.cpp's check: an
    // optimiser may turn the engine's branch on it into a select, and neither the select nor
    // what main passes on and returns is reported (-fno-sanitize-memory-param-retval). The mark's
    // teeth are memcheck's all the same: without it this program passes too (measured with clang
    // 18, 2026-11-18), since MemorySanitizer approximates a subtraction's shadow by its operands'
    // without the carry, so that BearSSL's EQ0, ~(q | -q) >> 31, of an accumulated difference
    // whose low byte is poisoned comes out initialised.
    bool const verdict = opened.has_value();
    memory_sanitizer::verdict(verdict);
    return check(verdict, "BearSSL GCM");
}

}  // namespace

int main() {
    int const failures =
        webcpp::test::constant_time::common_paths<memory_sanitizer>() + bearssl_gcm();
    std::printf("constant time under MemorySanitizer: %s\n", failures == 0 ? "ok" : "FAILED");
    return failures == 0 ? 0 : 1;
}
