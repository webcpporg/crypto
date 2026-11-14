// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Built with WEBCPP_CRYPTO_NO_EXCEPTIONS defined: random_device has no operator(), whose
// failure could not be reported, and fill is its interface.

#include <webcpp/crypto/random_device.hpp>

int main() {
    webcpp::crypto::random_device device;
    // expected-error@+1 {{type 'webcpp::crypto::random_device' does not provide a call operator}}
    return static_cast<int>(device());
}
