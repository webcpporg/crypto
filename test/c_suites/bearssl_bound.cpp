// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The bound of BearSSL's own test program (bearssl_test_crypto) under node. Upstream's C cannot
// call webcpp::test::bound, so this file, linked into the program, re-arms the bound at static
// initialisation, before main runs the suite. The default of 120 s is shorter than the suite,
// whose 88 tests take 116 s of CPU under Emscripten in a debug build (157 s on a loaded machine,
// 126 s natively); 900 s leaves room for a slower machine. Natively it does nothing.
#include <webcpp/test/exit_status.hpp>

#include <chrono>

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): a static initialiser is
// run for its effect, and nothing reads this.
[[maybe_unused]] bool const armed = (webcpp::test::bound(std::chrono::seconds(900)), true);

}  // namespace
