// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// MSVC's case of the fixture memory_missing_definition_install (spec section 8.6): a program that
// sets the memory option, calls install_memory_functions() and defines no
// webcpp::crypto::openssl_memory_resource() fails to link on that name, LNK2019 and LNK1120.
// The texts of ld64 and GNU ld are checked by tools/test/crypto_jamfiles_test.py.
#include <webcpp/crypto/backends/openssl.hpp>

int main() {
    return webcpp::crypto::backends::openssl::install_memory_functions() ? 0 : 1;
}
