// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// msan_test.cpp with a planted leak, a source of its own so that b2 compiles it with its own
// defines: the builds the lane expects MemorySanitizer to fail. With
// WEBCPP_TEST_CRYPTO_PLANTED_LEAK, a branch on a key byte before BearSSL's AES-GCM; with
// WEBCPP_TEST_CRYPTO_PLANTED_SCALAR_CHECK, a copy of P-256's scalar check that exits early on the
// first byte that differs (paths.hpp), run first.
#include "msan_test.cpp"  // NOLINT(bugprone-suspicious-include)
