// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A donation page that publishes one reusable address (BIP 352's silent payments): a pair of
// public keys, scan and spend. A donor's wallet with one input pays it: the output key it makes
// is new, tied to the donor's input. The recipient scans the transaction's outputs with its scan
// key pair, finds the payment, and makes the key pair that spends it with seckey_tweak_add. A
// second donation to the same address gives an output key unrelated to the first, so that an
// onlooker sees no two payments to one address. The address's encoding, the transaction and the
// smallest outpoint's choice are a wallet's (a domain library's); the keys are fixed here, so
// that the program runs the same each time, where a real wallet draws them from crypto's random
// device.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>
#include <webcpp/crypto/secret.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace secp256k1 = webcpp::crypto::curves::secp256k1;
namespace silent_payments = webcpp::crypto::curves::secp256k1::silent_payments;

namespace {

std::array<std::uint8_t, 32> repeated(std::uint8_t value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(value);
    return bytes;
}

using output_key = std::array<std::uint8_t, 32>;
using outpoint = std::array<std::uint8_t, silent_payments::outpoint_size>;

// The donor's wallet pays the address with one input: one output key, the transaction's.
bool pay(silent_payments::recipient const& address, secp256k1::keypair const& donor_input,
         outpoint const& smallest_outpoint, output_key& paid_key) {
    std::array<silent_payments::recipient, 1> const recipients{address};
    std::array<secp256k1::keypair const*, 1> const plain_inputs{&donor_input};
    std::array<output_key, 1> outputs{};
    // The workspace holds libsecp256k1's arrays and the input's secret; it is wiped on return.
    alignas(std::max_align_t) std::array<std::byte, silent_payments::send_workspace_size(1, 0, 1)>
        space{};
    if (!silent_payments::create_outputs(recipients, smallest_outpoint, {}, plain_inputs, outputs,
                                         space)) {
        return false;
    }
    paid_key = outputs[0];
    return true;
}

}  // namespace

int main() {
    // The donation page: its scan and spend key pairs stay with the recipient; the address is
    // their two public keys.
    auto const scan_pair = secp256k1::keypair::from_secret(repeated(0x51));
    // The spend secret is kept, in a secret<32> that wipes itself, to spend what is found.
    webcpp::crypto::secret<32> spend_secret;
    std::ranges::fill(spend_secret.writable(), std::uint8_t{0x52});
    auto const spend_pair = secp256k1::keypair::from_secret(spend_secret.bytes());
    auto const donor = secp256k1::keypair::from_secret(repeated(0x53));
    if (!scan_pair || !spend_pair || !donor) {
        return 1;
    }
    auto const scan_key = scan_pair->public_key();
    auto const spend_key = spend_pair->public_key();
    auto const donor_key = donor->public_key();
    if (!scan_key || !spend_key || !donor_key) {
        return 1;
    }
    silent_payments::recipient const address{.scan_key = *scan_key, .spend_key = *spend_key};

    // The donor pays: the transaction spends one input, whose outpoint is its smallest.
    outpoint first_outpoint{};
    first_outpoint.fill(0x01);
    output_key first_payment{};
    if (!pay(address, *donor, first_outpoint, first_payment)) {
        return 1;
    }

    // The recipient sees the transaction: its input's public key and smallest outpoint make the
    // summary, and the scan of its outputs finds the payment.
    std::array<secp256k1::public_key, 1> const input_keys{*donor_key};
    alignas(std::max_align_t) std::array<std::byte, silent_payments::summary_workspace_size(0, 1)>
        summary_space{};
    auto const summary =
        silent_payments::make_prevouts_summary(first_outpoint, {}, input_keys, summary_space);
    if (!summary) {
        return 1;
    }
    std::array<output_key, 1> const transaction_outputs{first_payment};
    std::array<silent_payments::found_output, 1> found{};
    alignas(std::max_align_t) std::array<std::byte, silent_payments::scan_workspace_size(1)>
        scan_space{};
    auto const found_count = silent_payments::scan_outputs(*scan_pair, *spend_key, *summary,
                                                           transaction_outputs, found, scan_space);
    if (!found_count) {
        return 1;
    }
    std::printf("the recipient found %zu output\n", *found_count);

    // The spend secret plus the found tweak is the output's secret key.
    auto const output_secret = secp256k1::seckey_tweak_add(spend_secret, found[0].spend_tweak);
    if (!output_secret) {
        return 1;
    }
    auto const spending_pair = secp256k1::keypair::from_secret(output_secret->bytes());
    if (!spending_pair) {
        return 1;
    }
    auto const spending_key = spending_pair->public_key();
    if (!spending_key || spending_key->xonly() != found[0].output_key) {
        return 1;
    }
    std::printf("the spending key matches the output\n");

    // A second donation from the same wallet, another transaction: another outpoint.
    outpoint second_outpoint{};
    second_outpoint.fill(0x02);
    output_key second_payment{};
    if (!pay(address, *donor, second_outpoint, second_payment)) {
        return 1;
    }
    if (second_payment != first_payment) {
        std::printf("two payments to one address share no output key\n");
    }
    return 0;
}

// end::program[]
