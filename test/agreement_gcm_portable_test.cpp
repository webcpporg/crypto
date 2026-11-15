// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// agreement_gcm_test.cpp with WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE, which the Jamfile
// defines: BearSSL on aes_ct64 and ghash_ctmul64 against OpenSSL. A source of its own, so
// that b2 compiles it with its own defines (spec section 4.3's pitfall); the code is shared.

#include "agreement_gcm_test.cpp"  // NOLINT(bugprone-suspicious-include): one program, twice
