// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Windows has no interposition of the C library's allocator (spec section 8.5): the count
// stays 0, the switch does nothing, and the programs say in their output that the C
// library is not counted; their other checks run.

#include <cstddef>

extern "C" {
std::size_t webcpp_test_c_allocations(void) {
    return 0;
}

void webcpp_test_count_c_allocations(int /*on*/) {}
}
