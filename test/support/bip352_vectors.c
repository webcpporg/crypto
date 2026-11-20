// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BIP 352's vectors, libsecp256k1's vectors.h compiled in C (on the include path of
// /third_party//secp256k1-test-config), handed to the C++ test through bip352_vectors.h.

#include "modules/silentpayments/vectors.h"

#include "bip352_vectors.h"

#include <stddef.h>

struct bip352_test_vector const* webcpp_test_bip352_vector(size_t index) {
    return &bip352_test_vectors[index];
}

size_t webcpp_test_bip352_vector_count(void) {
    return sizeof(bip352_test_vectors) / sizeof(bip352_test_vectors[0]);
}

void webcpp_test_bip352_layout(size_t* layout) {
    size_t const values[WEBCPP_TEST_BIP352_LAYOUT_SIZE] = {
        sizeof(struct bip352_recipient_addressdata),
        offsetof(struct bip352_recipient_addressdata, scan_pubkey),
        offsetof(struct bip352_recipient_addressdata, spend_pubkey),
        offsetof(struct bip352_recipient_addressdata, count),
        sizeof(struct bip352_receive_subtest),
        offsetof(struct bip352_receive_subtest, scan_seckey),
        offsetof(struct bip352_receive_subtest, spend_seckey),
        offsetof(struct bip352_receive_subtest, num_to_scan_outputs),
        offsetof(struct bip352_receive_subtest, to_scan_outputs),
        offsetof(struct bip352_receive_subtest, num_labels),
        offsetof(struct bip352_receive_subtest, label_integers),
        offsetof(struct bip352_receive_subtest, full_check),
        offsetof(struct bip352_receive_subtest, num_found_output_pubkeys),
        offsetof(struct bip352_receive_subtest, found_output_pubkeys),
        offsetof(struct bip352_receive_subtest, found_seckey_tweaks),
        offsetof(struct bip352_receive_subtest, found_signatures),
        sizeof(struct bip352_test_vector),
        offsetof(struct bip352_test_vector, num_plain_inputs),
        offsetof(struct bip352_test_vector, plain_seckeys),
        offsetof(struct bip352_test_vector, plain_pubkeys),
        offsetof(struct bip352_test_vector, num_taproot_inputs),
        offsetof(struct bip352_test_vector, taproot_seckeys),
        offsetof(struct bip352_test_vector, xonly_pubkeys),
        offsetof(struct bip352_test_vector, outpoint_smallest),
        offsetof(struct bip352_test_vector, num_outputs),
        offsetof(struct bip352_test_vector, num_recipient_entries),
        offsetof(struct bip352_test_vector, recipient_pubkeys),
        offsetof(struct bip352_test_vector, num_output_sets),
        offsetof(struct bip352_test_vector, num_recipient_outputs),
        offsetof(struct bip352_test_vector, recipient_outputs),
        offsetof(struct bip352_test_vector, num_receive_subtests),
        offsetof(struct bip352_test_vector, receive_subtests),
    };
    for (size_t at = 0; at < WEBCPP_TEST_BIP352_LAYOUT_SIZE; ++at) {
        layout[at] = values[at];
    }
}
