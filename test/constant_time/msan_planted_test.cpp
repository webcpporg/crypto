// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// msan_test.cpp with WEBCPP_TEST_CRYPTO_PLANTED_LEAK, a source of its own so that b2 compiles it
// with its own defines: the build the lane expects the checker to fail.
#include "msan_test.cpp"  // NOLINT(bugprone-suspicious-include)
