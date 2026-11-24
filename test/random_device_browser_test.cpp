// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On Emscripten under node, as a page meets it: with crypto.getRandomValues (and node's
// randomFillSync) throwing, random_device's fill returns entropy_unavailable with its output
// zeroed, and P-256's generate entropy_unavailable, the program running on; with the originals
// back, fill succeeds, from this translation unit and from a second one; with a globalThis.crypto
// whose getter throws, entropy_unavailable; with no globalThis.crypto (node 18's case), fill
// draws from require('node:crypto').webcrypto; with neither (an audio worklet's case), fill
// returns errc::not_supported. The test runs as a CommonJS program under node, where require is
// a function.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/random_device_second_unit.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>

#include <emscripten/em_asm.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace crypto = webcpp::crypto;

namespace {

// Every source a draw may reach throws, before any draw: the browser's, and node's own that
// Emscripten's getentropy takes while its MIN_NODE_VERSION is below 19.
// clang-format off: JavaScript, which clang-format would break
void plant_throwing_sources() {
    EM_ASM({
        const planted = () => { throw new Error('planted'); };
        globalThis.webcppSavedGetRandomValues = globalThis.crypto.getRandomValues;
        globalThis.crypto.getRandomValues = planted;
        if (typeof require === 'function') {
            const nodeCrypto = require('node:crypto');
            globalThis.webcppSavedRandomFillSync = nodeCrypto.randomFillSync;
            nodeCrypto.randomFillSync = planted;
        }
    });
}

void restore_sources() {
    EM_ASM({
        globalThis.crypto.getRandomValues = globalThis.webcppSavedGetRandomValues;
        if (typeof require === 'function') {
            require('node:crypto').randomFillSync = globalThis.webcppSavedRandomFillSync;
        }
    });
}

// A getter of globalThis.crypto that throws.
void plant_throwing_crypto_getter() {
    EM_ASM({
        Object.defineProperty(globalThis, 'crypto', {
            get() { throw new Error('planted getter'); },
            configurable: true
        });
    });
}

// Node 18 without --experimental-global-webcrypto has no globalThis.crypto.
void remove_global_crypto() {
    EM_ASM({
        Object.defineProperty(globalThis, 'crypto', {value: undefined, configurable: true});
    });
}

// An audio worklet has no crypto, and no node:crypto either: require's answer for it is
// replaced with a module that has no webcrypto.
void remove_node_crypto() {
    EM_ASM({
        const original = require;
        require = (name) => (name === 'node:crypto' ? {} : original(name));
    });
}

bool require_is_a_function() {
    return EM_ASM_INT({ return typeof require === 'function' ? 1 : 0; }) == 1;
}
// clang-format on

bool all_zero(std::vector<std::uint8_t> const& bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

}  // namespace

int main() {
    std::vector<std::uint8_t> buffer(300, 0xa5);

    plant_throwing_sources();
    auto filled = crypto::random_device{}.fill(buffer);
    BOOST_TEST(!filled && filled.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(all_zero(buffer));
    using keypair = crypto::curves::p256::basic_keypair<crypto::backends::bearssl>;
    auto const generated = keypair::generate();
    BOOST_TEST(!generated && generated.error() == crypto::error::entropy_unavailable);

    restore_sources();
    std::ranges::fill(buffer, 0xa5);
    filled = crypto::random_device{}.fill(buffer);
    BOOST_TEST(filled.has_value());
    BOOST_TEST(!all_zero(buffer));
    std::vector<std::uint8_t> second_unit_buffer(32, 0);
    BOOST_TEST(webcpp::test::fill_in_second_unit(second_unit_buffer).has_value());
    BOOST_TEST(!all_zero(second_unit_buffer));

    plant_throwing_crypto_getter();
    std::ranges::fill(buffer, 0xa5);
    filled = crypto::random_device{}.fill(buffer);
    BOOST_TEST(!filled && filled.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(all_zero(buffer));

    BOOST_TEST(require_is_a_function());
    remove_global_crypto();
    std::ranges::fill(buffer, 0);
    filled = crypto::random_device{}.fill(buffer);
    BOOST_TEST(filled.has_value());
    BOOST_TEST(!all_zero(buffer));

    remove_node_crypto();
    std::ranges::fill(buffer, 0xa5);
    filled = crypto::random_device{}.fill(buffer);
    BOOST_TEST(!filled && filled.error() == boost::system::errc::not_supported);
    BOOST_TEST(all_zero(buffer));
    return webcpp::test::exit_status(boost::report_errors());
}
