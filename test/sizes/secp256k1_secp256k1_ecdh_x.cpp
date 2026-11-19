// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The size of secp256k1's ecdh_x on libsecp256k1: bench/operations.hpp's secp256k1_ecdh_x, once
// (test/sizes/Jamfile).

#include <webcpp/crypto/backends/secp256k1.hpp>

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<
        webcpp::crypto::bench::secp256k1_ecdh_x<webcpp::crypto::backends::secp256k1>>(
        argument_count);
}
