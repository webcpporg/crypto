// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On Emscripten under node, crypto's entropy as libsodium's generator leaves no copy of a draw
// in the stack it used: the 4 bytes of sodium_ready's probe, and the 4 bytes randombytes_random
// returns, are zero in the module's memory below the stack pointer once the call has returned,
// read at -O2 (the Jamfile's requirements), where a wipe the optimiser may drop as a dead store
// would be dropped. crypto.getRandomValues is planted to fill every array with a pattern of 4
// bytes, one per call; each call runs in a function that is never inlined, under 1 KiB of
// padding, so that its frame is gone when it returns and the calls that read the stack do not
// reach it; a positive control, a call that leaves a third pattern in its frame unwiped, shows
// the scan reaches such a frame. The stack's free part, from its end up to the stack pointer, is
// read from JavaScript, whose reads of the module's memory are well defined. The test runs as a
// CommonJS program under node.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <sodium/randombytes.h>

#include <emscripten/em_asm.h>
#include <emscripten/stack.h>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

namespace {

// The probe's pattern, then randombytes_random's.
constexpr std::array<std::uint8_t, 4> probe_pattern{0x5e, 0xc7, 0x3a, 0x91};
constexpr std::array<std::uint8_t, 4> random_pattern{0xd2, 0x49, 0xb6, 0x0f};
// The positive control's pattern, which a call leaves on the stack unwiped.
constexpr std::array<std::uint8_t, 4> control_pattern{0x83, 0x1e, 0xf4, 0x6a};

// Runs `call` in a frame of its own under 1 KiB of the stack, and returns what it returns.
template <class Call>
__attribute__((noinline)) bool under_padding(Call call) {
    std::array<std::uint8_t volatile, 1024> padding{};
    padding[0] = 1;
    return call();
}

// The calls that draw, never inlined.
__attribute__((noinline)) bool first_sodium_call() {
    return webcpp::crypto::detail::sodium_ready().has_value();
}

// The positive control: writes the control pattern into its frame and returns without wiping,
// so that the scan must find it; were the stack's layout to change so that the scan no longer
// reaches a dead frame under the padding, this fails instead of the checks passing vacuously.
__attribute__((noinline)) bool leaves_pattern() {
    std::array<std::uint8_t volatile, 4> left_bytes{};
    for (std::size_t index = 0; index < left_bytes.size(); ++index) {
        left_bytes[index] = control_pattern[index];
    }
    return left_bytes[0] == control_pattern[0];
}

__attribute__((noinline)) bool random_is_pattern() {
    return randombytes_random() == std::bit_cast<std::uint32_t>(random_pattern);
}

// clang-format off: JavaScript, which clang-format would break
// crypto.getRandomValues fills every array with `pattern`'s 4 bytes, repeated.
void plant_pattern(std::array<std::uint8_t, 4> const& pattern) {
    EM_ASM({
        const pattern = HEAPU8.slice($0, $0 + 4);
        globalThis.crypto.getRandomValues = (array) => {
            for (let index = 0; index < array.length; ++index) array[index] = pattern[index % 4];
            return array;
        };
    }, pattern.data());
}

// Whether `pattern`'s 4 bytes appear anywhere in the stack's free part, from its end up to the
// stack pointer of the caller.
bool pattern_below_stack_pointer(std::array<std::uint8_t, 4> const& pattern) {
    return EM_ASM_INT({
        const pattern = HEAPU8.slice($0, $0 + 4);
        for (let address = $1; address + 4 <= $2; ++address) {
            if (HEAPU8[address] === pattern[0] && HEAPU8[address + 1] === pattern[1] &&
                HEAPU8[address + 2] === pattern[2] && HEAPU8[address + 3] === pattern[3]) {
                return 1;
            }
        }
        return 0;
    }, pattern.data(), emscripten_stack_get_end(), emscripten_stack_get_current()) == 1;
}
// clang-format on

}  // namespace

int main() {
    // The scan finds a draw's copy that a call leaves behind.
    bool const control_written = under_padding(leaves_pattern);
    BOOST_TEST(pattern_below_stack_pointer(control_pattern));
    BOOST_TEST(control_written);

    // The first libsodium call of the program: its probe draws the pattern, then sodium_init its
    // canary, into libsodium's own storage.
    plant_pattern(probe_pattern);
    bool const initialised = under_padding(first_sodium_call);
    BOOST_TEST(!pattern_below_stack_pointer(probe_pattern));
    BOOST_TEST(initialised);

    plant_pattern(random_pattern);
    bool const drawn_is_pattern = under_padding(random_is_pattern);
    BOOST_TEST(!pattern_below_stack_pointer(random_pattern));
    BOOST_TEST(drawn_is_pattern);
    return webcpp::test::exit_status(boost::report_errors());
}
