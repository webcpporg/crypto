// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto spells out the names libsecp256k1 abbreviates (design D12, R24): silent payments' summary
// of the previous outputs is previous_outputs_summary, made by make_previous_outputs_summary, with
// no alias left at libsecp256k1's prevouts. A program that still names either stops there, with
// those two errors alone, although silent_payments.hpp is included.

#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>

// clang-format off
// expected-error@+1 {{no member named 'prevouts_summary' in namespace 'webcpp::crypto::curves::secp256k1::silent_payments'}}
using webcpp::crypto::curves::secp256k1::silent_payments::prevouts_summary;
// expected-error@+1 {{no member named 'make_prevouts_summary' in namespace 'webcpp::crypto::curves::secp256k1::silent_payments'}}
using webcpp::crypto::curves::secp256k1::silent_payments::make_prevouts_summary;
// clang-format on

int main() {
    return 0;
}
