// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The constant-time comparison's header is constant_time_equal.hpp, with no header left at the old
// path (design D10): a program that still includes equal.hpp stops at the include, with that error
// alone.

// expected-error@+1 {{'webcpp/crypto/equal.hpp' file not found}}
#include <webcpp/crypto/equal.hpp>

int main() {
    return 0;
}
