// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The main of BearSSL's own test program (bearssl_test_crypto). Upstream's C cannot call
// webcpp::test::bound, and its main lists the tests and returns 0 for any argument but a test's
// name or "all", so a lane whose argument did not arrive would pass having run nothing. The Jamfile
// renames upstream's main to bearssl_test_main; this one runs it only for the argument "all",
// else fails.
//
// The bound is re-armed at static initialisation, before main: node's default of 120 s is shorter
// than the 88 tests, which take 116 s of CPU under Emscripten in a debug build (157 s on a loaded
// machine, 126 s natively); 900 s leaves room for a slower machine. Natively it does nothing.
#include <webcpp/test/exit_status.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>

#undef main

extern "C" int bearssl_test_main(int argc, char** argv);

namespace {

// NOLINTNEXTLINE(bugprone-throwing-static-initialization): run for its effect; nothing reads it
[[maybe_unused]] bool const armed = (webcpp::test::bound(std::chrono::seconds(900)), true);

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 || std::strcmp(argv[1], "all") != 0) {
        // NOLINTNEXTLINE(cert-err33-c): the program fails either way; nothing to do if stderr fails
        std::fputs("bearssl_test_crypto: the argument all did not arrive, so no test ran\n",
                   stderr);
        return webcpp::test::exit_status(1);
    }
    return webcpp::test::exit_status(bearssl_test_main(argc, argv));
}
