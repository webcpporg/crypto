// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The size of Ed25519 on libsodium: bench/operations.hpp's ed25519, once (test/sizes/Jamfile).

#include <webcpp/crypto/backends/sodium.hpp>

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<
        webcpp::crypto::bench::ed25519<webcpp::crypto::backends::sodium>>(argument_count);
}
