// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What every sized program of test/sizes/Jamfile does: the operation of bench/operations.hpp,
// made from a byte the compiler cannot know (the count of the program's arguments), run once, and
// a byte of its result printed, so that the optimiser keeps both. The baseline prints a line too.

#ifndef WEBCPP_CRYPTO_TEST_SIZES_SIZED_HPP
#define WEBCPP_CRYPTO_TEST_SIZES_SIZED_HPP

#include "operations.hpp"

#include <cstdint>
#include <cstdio>

namespace webcpp::crypto::test {

// Runs Operation once, made from argument_count, and prints a byte of its result.
template <class Operation>
int sized(int argument_count) {
    Operation operation(static_cast<std::uint8_t>(argument_count));
    std::printf("%02x\n", static_cast<unsigned>(operation.run()));
    return 0;
}

}  // namespace webcpp::crypto::test

#endif  // WEBCPP_CRYPTO_TEST_SIZES_SIZED_HPP
