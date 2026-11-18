// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The baseline of test/sizes/Jamfile: a program that prints a line and calls nothing of crypto,
// whose size every sized program's is read against.

#include <cstdio>

int main() {
    std::puts("baseline");
    return 0;
}
