// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The secret type that wipes itself is webcpp::secure's secret<N>, with no alias left in
// crypto: a program that still names crypto::secret<16> stops at the name, with that error alone,
// although crypto's convenience header is included.

#include <webcpp/crypto.hpp>

int main() {
    // expected-error@+1 {{no template named 'secret' in namespace 'webcpp::crypto'}}
    webcpp::crypto::secret<16> const key_bytes;
    return static_cast<int>(key_bytes.bytes().size());
}
