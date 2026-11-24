// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free asynchronous AEAD forms are secret_key_encryption::aead's, with no alias left in
// crypto:: (design D11): a program that still names crypto::async_seal or crypto::async_open stops
// at each, with those two errors alone, although async.hpp, which brings the new forms, is
// included. The names are declared, not called; async_seal_removed calls them.

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

// expected-error@+1 {{no member named 'async_seal' in namespace 'webcpp::crypto'}}
using webcpp::crypto::async_seal;
// expected-error@+1 {{no member named 'async_open' in namespace 'webcpp::crypto'}}
using webcpp::crypto::async_open;

int main() {
    return 0;
}
