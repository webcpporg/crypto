// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// MemorySanitizer's poisoning (spec section 8.3): the key, the plaintext, the block and the tag
// are poisoned, and a branch or an index that depends on them, in webcpp's code, BearSSL's or
// ctaes's, all instrumented, ends the run with a report.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/equal.hpp>

#include <sanitizer/msan_interface.h>

#include <array>
#include <cstdint>
#include <cstdio>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    __msan_poison(a.data(), a.size());
    __msan_poison(b.data(), b.size());
    bool same = crypto::equal(a, b);
    __msan_unpoison(&same, sizeof same);

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
    __msan_check_mem_is_initialized(&verdict, sizeof verdict);

    // ctaes's make, encrypt and decrypt with the key and the block poisoned.
    std::array<std::uint8_t, 16> block{};
    __msan_poison(key.data(), key.size());
    __msan_poison(block.data(), block.size());
    auto block_cipher = crypto::ciphers::aes256<crypto::backends::ctaes>::make(key);
    bool const block_ok =
        block_cipher && block_cipher->encrypt(block) && block_cipher->decrypt(block);

    bool const ok = verdict && block_ok && same;
    std::printf("constant time under MemorySanitizer: %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}
