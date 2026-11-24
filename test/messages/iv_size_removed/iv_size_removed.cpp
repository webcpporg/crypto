// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto spells its names out (design D11, R22): a nonce's size is nonce_size and its error
// invalid_nonce_size, with no alias left at the old names. A program that still names iv_size or
// invalid_iv_size stops at each, with those two errors alone.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/error.hpp>

#include <cstddef>

int main() {
    namespace crypto = webcpp::crypto;
    // expected-error@+1 {{no member named 'iv_size' in}}
    std::size_t const size = crypto::ciphers::xchacha20_poly1305<>::iv_size;
    // expected-error@+1 {{no member named 'invalid_iv_size' in}}
    auto const refusal = crypto::error::invalid_iv_size;
    return size == 24 && static_cast<int>(refusal) == 2 ? 0 : 1;
}
