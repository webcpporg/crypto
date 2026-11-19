// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The baseline of test/sizes/Jamfile: the harness of every sized program (sized.hpp: an operation
// made from the argument count, run once, its result taken or refused, a byte printed) around
// bench/operations.hpp's nothing, which calls nothing of crypto. Each sized program's size is
// read against it, so that what a cell adds is its operation's code alone.

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<webcpp::crypto::bench::nothing>(argument_count);
}
