// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The size of BIP 352 silent payments on libsecp256k1: bench/operations.hpp's
// secp256k1_silent_payments, once (test/sizes/Jamfile).

#include <webcpp/crypto/backends/secp256k1.hpp>

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<
        webcpp::crypto::bench::secp256k1_silent_payments<webcpp::crypto::backends::secp256k1>>(
        argument_count);
}
