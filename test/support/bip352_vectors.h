// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BIP 352's send and receive vectors as libsecp256k1's own test reads them: the cases of
// src/modules/silentpayments/vectors.h, which libsecp256k1's tools/tests_silentpayments_generate.py
// derives from its copy of BIP 352's send_and_receive_test_vectors.json (the superproject's
// test_bip352_vectors_match_libsecp256k1 checks that copy is BIP 352's, byte for byte). The data
// is compiled in C, by bip352_vectors.c, with warnings off as libsecp256k1's own sources are:
// vectors.h is about 37 MB of static arrays, partly initialised from string literals, which the
// C++ test's warnings, MSVC's among them, would refuse.
//
// C sees the structs in vectors.h, which bip352_vectors.c includes first. C++ sees the copy
// below, made from vectors.h at libsecp256k1's pin with a std::array for each C array (the same
// layout); webcpp_test_bip352_layout gives the C compiler's sizes and offsets of every field,
// which the C++ test compares with its own, so that the copy cannot drift from what the C file
// holds unseen.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_BIP352_VECTORS_H
#define WEBCPP_TEST_CRYPTO_SUPPORT_BIP352_VECTORS_H

#include <stddef.h>

#ifdef __cplusplus

#include <array>

#define MAX_INPUTS_PER_TEST_CASE 3
#define MAX_OUTPUTS_PER_TEST_CASE 2324
#define MAX_RECIPIENT_ENTRIES_PER_TEST_CASE 4
#define MAX_LABELS_PER_TEST_CASE 4
#define MAX_PERMUTATIONS_PER_SENDING_TEST_CASE 12
#define MAX_RECEIVE_SUBTESTS 2

extern "C" {

/** A recipient's address data: its scan and spend keys, and how many outputs it is paid. */
struct bip352_recipient_addressdata {
    /** The scan key, SEC1 compressed. */
    std::array<unsigned char, 33> scan_pubkey;
    /** The spend key, SEC1 compressed. */
    std::array<unsigned char, 33> spend_pubkey;
    /** How many outputs the sender makes for this address. */
    size_t count;
};

/** One receiving subtest: the recipient's keys, the outputs to scan, and what is found. */
struct bip352_receive_subtest {
    /** The scan secret key. */
    std::array<unsigned char, 32> scan_seckey;
    /** The spend secret key. */
    std::array<unsigned char, 32> spend_seckey;
    /** How many outputs the transaction has. */
    size_t num_to_scan_outputs;
    /** The transaction's x-only output keys. */
    std::array<std::array<unsigned char, 32>, MAX_OUTPUTS_PER_TEST_CASE> to_scan_outputs;
    /** How many labels the recipient uses. */
    size_t num_labels;
    /** The labels' integers m. */
    std::array<unsigned int, MAX_LABELS_PER_TEST_CASE> label_integers;
    /** 1 to check keys, tweaks and signatures; 0 to check the count alone. */
    size_t full_check;
    /** How many outputs the scan finds. */
    size_t num_found_output_pubkeys;
    /** The found outputs' x-only keys. */
    std::array<std::array<unsigned char, 32>, MAX_OUTPUTS_PER_TEST_CASE> found_output_pubkeys;
    /** The found outputs' spend tweaks. */
    std::array<std::array<unsigned char, 32>, MAX_OUTPUTS_PER_TEST_CASE> found_seckey_tweaks;
    /** The BIP 340 signature by each found output's key. */
    std::array<std::array<unsigned char, 64>, MAX_OUTPUTS_PER_TEST_CASE> found_signatures;
};

/** One case: the inputs, the smallest outpoint, the recipients, the outputs, the subtests. */
struct bip352_test_vector {
    /** How many plain (not Taproot) eligible inputs there are. */
    size_t num_plain_inputs;
    /** Their secret keys. */
    std::array<std::array<unsigned char, 32>, MAX_INPUTS_PER_TEST_CASE> plain_seckeys;
    /** Their public keys, SEC1 compressed. */
    std::array<std::array<unsigned char, 33>, MAX_INPUTS_PER_TEST_CASE> plain_pubkeys;
    /** How many Taproot inputs there are. */
    size_t num_taproot_inputs;
    /** Their secret keys. */
    std::array<std::array<unsigned char, 32>, MAX_INPUTS_PER_TEST_CASE> taproot_seckeys;
    /** Their x-only public keys. */
    std::array<std::array<unsigned char, 32>, MAX_INPUTS_PER_TEST_CASE> xonly_pubkeys;
    /** The transaction's smallest outpoint, serialised. */
    std::array<unsigned char, 36> outpoint_smallest;
    /** How many outputs the sender makes, the recipients' counts summed. */
    size_t num_outputs;
    /** How many recipient entries there are. */
    size_t num_recipient_entries;
    /** The recipients, each with its count. */
    std::array<bip352_recipient_addressdata, MAX_RECIPIENT_ENTRIES_PER_TEST_CASE> recipient_pubkeys;
    /** How many orders of the outputs are correct. */
    size_t num_output_sets;
    /** How many outputs each order has; 0 when sending fails. */
    size_t num_recipient_outputs;
    /** The correct orders of the outputs' x-only keys. */
    std::array<std::array<std::array<unsigned char, 32>, MAX_OUTPUTS_PER_TEST_CASE>,
               MAX_PERMUTATIONS_PER_SENDING_TEST_CASE>
        recipient_outputs;
    /** How many receiving subtests there are. */
    size_t num_receive_subtests;
    /** The receiving subtests. */
    std::array<bip352_receive_subtest, MAX_RECEIVE_SUBTESTS> receive_subtests;
};

#endif

/** The number of values webcpp_test_bip352_layout writes. */
#define WEBCPP_TEST_BIP352_LAYOUT_SIZE 32

/**
 * The case at `index`, below webcpp_test_bip352_vector_count().
 *
 * @param index The case's index.
 * @return The case, static data.
 */
struct bip352_test_vector const* webcpp_test_bip352_vector(size_t index);

/**
 * The number of cases.
 *
 * @return 28 at libsecp256k1's pin.
 */
size_t webcpp_test_bip352_vector_count(void);

/**
 * The C compiler's sizes of the three structs and offsets of their fields, in the order the C++
 * test lists them.
 *
 * @param layout Where the WEBCPP_TEST_BIP352_LAYOUT_SIZE values go.
 */
void webcpp_test_bip352_layout(size_t* layout);

#ifdef __cplusplus
}
#endif

#endif
