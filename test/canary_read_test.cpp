// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::read_canary keeps the load of the canary in an optimised build, on every
// compiler: test/Jamfile builds this program at full optimisation without the canary,
// which must not link, and with it, which must link and run. gcc drops a volatile glvalue
// converted to void ("conversion to void will not access object"): with that form the
// program without the canary linked, and a backend's link-time check would not fire.

#include <webcpp/crypto/detail/engines.hpp>

// A test's own canary, defined only when WEBCPP_TEST_CRYPTO_DEFINE_CANARY is.
extern "C" const char webcpp_crypto_test_canary;
#ifdef WEBCPP_TEST_CRYPTO_DEFINE_CANARY
extern "C" const char webcpp_crypto_test_canary = 0;
#endif

int main() {
    webcpp::crypto::detail::read_canary(webcpp_crypto_test_canary);
    return 0;
}
