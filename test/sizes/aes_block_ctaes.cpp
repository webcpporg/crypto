// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The size of the AES block cipher on ctaes: bench/operations.hpp's aes_block, once
// (test/sizes/Jamfile).

#include <webcpp/crypto/backends/ctaes.hpp>

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<
        webcpp::crypto::bench::aes_block<webcpp::crypto::backends::ctaes>>(argument_count);
}
