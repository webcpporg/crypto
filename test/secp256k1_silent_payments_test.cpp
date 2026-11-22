// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's silent payments against BIP 352's vectors, read as libsecp256k1's own test reads
// them (support/bip352_vectors.h): each case's input keys, smallest outpoint and recipients'
// keys, already taken out of its transactions and addresses, which is the protocol's part.
// Sending, the 28 cases: create_outputs with key pairs of the plain and Taproot secret keys and
// each recipient repeated `count` times; the outputs match one of the case's orders; the three
// cases with no expected output are refused: no input at all and 2324 recipients on one scan key
// (more than group_limit) with invalid_input_size, input keys that sum to zero with
// invalid_secret_key. Receiving, the 29 subtests: make_prevouts_summary (refused where nothing
// is found: invalid_input_size with no input key, invalid_public_key for keys that sum to
// infinity), the labels of label_integers with create_label, scan_outputs with a lookup over
// them; where full_check is set, every found output's key and spend tweak are among the case's,
// and the BIP 340 signature by keypair::make(seckey_tweak_add(spend secret, spend tweak)) of
// SHA-256("message") with the auxiliary randomness SHA-256("random auxiliary data") equals the
// case's; the found count equals the case's; an output found with a label has a label the lookup
// knows, one found without has none. Then a labelled address round trip, and every refusal:
// no recipient, no input, outputs not one per recipient, no output key, no input key, a short
// workspace, `found` shorter than the outputs, an output key that does not parse, a moved-from
// key pair, a null pointer among the inputs, a labelled spend key at infinity, the group limit
// counted after a refusal (a sum of zero over two groups, a group over it); inputs of one kind
// only, the other side an emptied vector whose data() is not null, run without abort. Every
// workspace is zero afterwards.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/bip352_vectors.h"
#include "support/secp256k1_checks.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace sp = webcpp::crypto::curves::secp256k1::silent_payments;

namespace {

using scalar = std::array<std::uint8_t, 32>;
using xonly = std::array<std::uint8_t, 32>;

// The summary is made only by make_prevouts_summary; it is public and copied freely.
static_assert(!std::is_default_constructible_v<sp::prevouts_summary>);
static_assert(std::is_copy_constructible_v<sp::prevouts_summary>);
static_assert(sp::outpoint_size == 36);
static_assert(sp::group_limit == 2323);
static_assert(sp::send_workspace_size(2, 1, 3) ==
              (2 * (sizeof(secp256k1_silentpayments_recipient) + sizeof(void*) +
                    sizeof(secp256k1_xonly_pubkey) + sizeof(void*))) +
                  (1 * sizeof(void*)) + (3 * (32 + sizeof(void*))) +
                  (7 * alignof(std::max_align_t)));
static_assert(sp::summary_workspace_size(2, 3) ==
              (2 * (sizeof(secp256k1_xonly_pubkey) + sizeof(void*))) + (3 * sizeof(void*)) +
                  (3 * alignof(std::max_align_t)));
static_assert(sp::scan_workspace_size(4) ==
              (4 * (sizeof(secp256k1_xonly_pubkey) + sizeof(void*) +
                    sizeof(secp256k1_silentpayments_found_output) + sizeof(void*))) +
                  (4 * alignof(std::max_align_t)));

// A lookup must be noexcept: an exception must not cross libsecp256k1's C frames.
struct throwing_lookup {
    std::optional<std::span<std::uint8_t const, 32>> operator()(
        std::span<std::uint8_t const, 33> /*candidate*/) const {
        return std::nullopt;
    }
};

struct quiet_lookup {
    std::optional<std::span<std::uint8_t const, 32>> operator()(
        std::span<std::uint8_t const, 33> /*candidate*/) const noexcept {
        return std::nullopt;
    }
};

// Lookups whose result only converts to the concept's type are refused: a span made from a
// result returned by value would point into a temporary that is gone when libsecp256k1 reads
// the tweak. libstdc++'s and MSVC's optional convert these noexcept, libc++'s does not, so the
// gcc-15 lane is where a looser concept would accept them.
struct tweak_by_value_lookup {
    std::optional<std::array<std::uint8_t, 32>> operator()(
        std::span<std::uint8_t const, 33> /*candidate*/) const noexcept {
        return std::nullopt;
    }
};

struct array_lookup {
    std::array<std::uint8_t, 32> operator()(
        std::span<std::uint8_t const, 33> /*candidate*/) const noexcept {
        return {};
    }
};

struct converting_lookup {
    std::nullopt_t operator()(std::span<std::uint8_t const, 33> /*candidate*/) const noexcept {
        return std::nullopt;
    }
};

static_assert(sp::label_lookup<sp::no_labels>);
static_assert(sp::label_lookup<quiet_lookup>);
static_assert(!sp::label_lookup<throwing_lookup>);
static_assert(!sp::label_lookup<tweak_by_value_lookup>);
static_assert(!sp::label_lookup<array_lookup>);
static_assert(!sp::label_lookup<converting_lookup>);

// Whether scan_outputs takes `Lookup`.
template <class Lookup>
constexpr bool scans_with = requires(secp::keypair const& scan_key, secp::public_key const& spend,
                                     sp::prevouts_summary const& summary, Lookup const& lookup) {
    sp::scan_outputs(scan_key, spend, summary, std::span<xonly const>{},
                     std::span<sp::found_output>{}, secp::workspace{}, lookup);
};
static_assert(scans_with<quiet_lookup>);
static_assert(!scans_with<throwing_lookup>);
static_assert(!scans_with<tweak_by_value_lookup>);
static_assert(!scans_with<array_lookup>);

// A workspace on the heap, filled with non-zero bytes, so that its wipe is seen.
std::vector<std::byte> lent(std::size_t size) {
    return std::vector<std::byte>(size, std::byte{0xa5});
}

bool all_zero(std::span<std::byte const> space) {
    return std::ranges::all_of(space, [](std::byte b) { return b == std::byte{0}; });
}

secp::keypair keypair_of(std::span<std::uint8_t const, 32> secret_bytes) {
    auto made = secp::keypair::make(secret_bytes);
    if (!BOOST_TEST(made.has_value())) {
        std::exit(boost::report_errors());
    }
    return std::move(*made);
}

secp::public_key public_of(secp::keypair const& key) {
    auto const encoded = key.public_key();
    if (!BOOST_TEST(encoded.has_value())) {
        std::exit(boost::report_errors());
    }
    auto const parsed = secp::parse_public_key(*encoded);
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

secp::public_key parsed_key(std::span<std::uint8_t const> encoded) {
    auto const parsed = secp::parse_public_key(encoded);
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

scalar sha256_of(std::string_view text) {
    boost::hash2::sha2_256 hasher;
    hasher.update(text.data(), text.size());
    auto const digest = hasher.result();
    scalar out{};
    std::ranges::copy(digest, out.begin());
    return out;
}

// The C compiler's layout of the vectors' structs is the C++ copy's.
void layout() {
    std::array<std::size_t, WEBCPP_TEST_BIP352_LAYOUT_SIZE> c_layout{};
    webcpp_test_bip352_layout(c_layout.data());
    std::array<std::size_t, WEBCPP_TEST_BIP352_LAYOUT_SIZE> const cpp_layout{
        sizeof(bip352_recipient_addressdata),
        offsetof(bip352_recipient_addressdata, scan_pubkey),
        offsetof(bip352_recipient_addressdata, spend_pubkey),
        offsetof(bip352_recipient_addressdata, count),
        sizeof(bip352_receive_subtest),
        offsetof(bip352_receive_subtest, scan_seckey),
        offsetof(bip352_receive_subtest, spend_seckey),
        offsetof(bip352_receive_subtest, num_to_scan_outputs),
        offsetof(bip352_receive_subtest, to_scan_outputs),
        offsetof(bip352_receive_subtest, num_labels),
        offsetof(bip352_receive_subtest, label_integers),
        offsetof(bip352_receive_subtest, full_check),
        offsetof(bip352_receive_subtest, num_found_output_pubkeys),
        offsetof(bip352_receive_subtest, found_output_pubkeys),
        offsetof(bip352_receive_subtest, found_seckey_tweaks),
        offsetof(bip352_receive_subtest, found_signatures),
        sizeof(bip352_test_vector),
        offsetof(bip352_test_vector, num_plain_inputs),
        offsetof(bip352_test_vector, plain_seckeys),
        offsetof(bip352_test_vector, plain_pubkeys),
        offsetof(bip352_test_vector, num_taproot_inputs),
        offsetof(bip352_test_vector, taproot_seckeys),
        offsetof(bip352_test_vector, xonly_pubkeys),
        offsetof(bip352_test_vector, outpoint_smallest),
        offsetof(bip352_test_vector, num_outputs),
        offsetof(bip352_test_vector, num_recipient_entries),
        offsetof(bip352_test_vector, recipient_pubkeys),
        offsetof(bip352_test_vector, num_output_sets),
        offsetof(bip352_test_vector, num_recipient_outputs),
        offsetof(bip352_test_vector, recipient_outputs),
        offsetof(bip352_test_vector, num_receive_subtests),
        offsetof(bip352_test_vector, receive_subtests),
    };
    if (!BOOST_TEST(c_layout == cpp_layout)) {
        std::exit(boost::report_errors());
    }
    BOOST_TEST_EQ(webcpp_test_bip352_vector_count(), 28U);
}

// The key pairs of a case's inputs, and pointers to them.
struct inputs {
    std::vector<secp::keypair> taproot;
    std::vector<secp::keypair> plain;
    std::vector<secp::keypair const*> taproot_pointers;
    std::vector<secp::keypair const*> plain_pointers;
};

inputs inputs_of(bip352_test_vector const& test) {
    inputs made;
    made.taproot.reserve(test.num_taproot_inputs);
    made.plain.reserve(test.num_plain_inputs);
    for (std::size_t i = 0; i < test.num_taproot_inputs; ++i) {
        made.taproot.push_back(keypair_of(test.taproot_seckeys[i]));
    }
    for (std::size_t i = 0; i < test.num_plain_inputs; ++i) {
        made.plain.push_back(keypair_of(test.plain_seckeys[i]));
    }
    made.taproot_pointers.reserve(made.taproot.size());
    made.plain_pointers.reserve(made.plain.size());
    for (auto const& key : made.taproot) {
        made.taproot_pointers.push_back(&key);
    }
    for (auto const& key : made.plain) {
        made.plain_pointers.push_back(&key);
    }
    return made;
}

// A case's recipients, each repeated `count` times.
std::vector<sp::recipient> recipients_of(bip352_test_vector const& test) {
    std::vector<sp::recipient> recipients;
    recipients.reserve(test.num_outputs);
    for (std::size_t entry = 0; entry < test.num_recipient_entries; ++entry) {
        auto const& address = test.recipient_pubkeys[entry];
        auto const scan_key = parsed_key(address.scan_pubkey);
        auto const spend_key = parsed_key(address.spend_pubkey);
        for (std::size_t copy = 0; copy < address.count; ++copy) {
            recipients.push_back(sp::recipient{.scan_key = scan_key, .spend_key = spend_key});
        }
    }
    return recipients;
}

// Why a case with no expected output is refused: no input at all and a group over the limit
// are counted by webcpp, a sum of zero is libsecp256k1's.
crypto::error send_refusal(bip352_test_vector const& test, std::size_t recipient_count) {
    if (test.num_taproot_inputs == 0 && test.num_plain_inputs == 0) {
        return crypto::error::invalid_input_size;
    }
    if (recipient_count > sp::group_limit) {
        return crypto::error::invalid_input_size;
    }
    return crypto::error::invalid_secret_key;
}

// Whether every output is in one of the case's orders of its expected outputs.
bool in_one_order(bip352_test_vector const& test, std::span<xonly const> outputs) {
    for (std::size_t order = 0; order < test.num_output_sets; ++order) {
        auto const listed = [&](xonly const& output) {
            auto const expected =
                std::span(test.recipient_outputs[order]).first(test.num_recipient_outputs);
            return std::ranges::any_of(
                expected, [&](auto const& key) { return std::ranges::equal(output, key); });
        };
        if (std::cmp_equal(std::ranges::count_if(outputs, listed), test.num_recipient_outputs)) {
            return true;
        }
    }
    return false;
}

struct send_counts {
    int matched = 0;
    int refused = 0;
};

void send_one(std::size_t case_index, send_counts& counts) {
    auto const& test = *webcpp_test_bip352_vector(case_index);
    auto const recipients = recipients_of(test);
    BOOST_TEST_EQ(recipients.size(), test.num_outputs);
    auto const made = inputs_of(test);
    std::vector<xonly> outputs(recipients.size());
    auto space =
        lent(sp::send_workspace_size(recipients.size(), made.taproot.size(), made.plain.size()));
    auto const sent =
        sp::create_outputs(recipients, std::span<std::uint8_t const, 36>(test.outpoint_smallest),
                           made.taproot_pointers, made.plain_pointers, outputs, space);
    BOOST_TEST(all_zero(space));
    if (test.num_recipient_outputs == 0) {
        if (BOOST_TEST(!sent.has_value())) {
            BOOST_TEST(sent.error() == send_refusal(test, recipients.size()));
        }
        ++counts.refused;
        return;
    }
    if (!BOOST_TEST(sent.has_value())) {
        std::cerr << "sending case " << case_index << " refused\n";
        return;
    }
    if (BOOST_TEST(in_one_order(test, outputs))) {
        ++counts.matched;
    } else {
        std::cerr << "sending case " << case_index << " gave other outputs\n";
    }
}

void sending() {
    send_counts counts;
    for (std::size_t case_index = 0; case_index < webcpp_test_bip352_vector_count(); ++case_index) {
        send_one(case_index, counts);
    }
    std::cout << "sending: matched=" << counts.matched << " refused=" << counts.refused << '\n';
    BOOST_TEST_EQ(counts.matched, 25);
    BOOST_TEST_EQ(counts.refused, 3);
}

// The labels a recipient knows, and the lookup over them.
struct label_cache {
    std::vector<sp::label> labels;

    std::optional<std::span<std::uint8_t const, 32>> operator()(
        std::span<std::uint8_t const, 33> candidate) const noexcept {
        for (auto const& known : labels) {
            if (std::ranges::equal(known.point, candidate)) {
                return std::span<std::uint8_t const, 32>(known.tweak);
            }
        }
        return std::nullopt;
    }
};

struct receive_counts {
    int scanned = 0;
    int refused = 0;
    int full_checks = 0;
    int found = 0;
};

// The case's summary, or nothing where the case expects it refused.
std::optional<sp::prevouts_summary> summary_of(bip352_test_vector const& test,
                                               bip352_receive_subtest const& subtest) {
    std::vector<xonly> taproot_keys;
    taproot_keys.reserve(test.num_taproot_inputs);
    for (std::size_t i = 0; i < test.num_taproot_inputs; ++i) {
        taproot_keys.push_back(test.xonly_pubkeys[i]);
    }
    std::vector<secp::public_key> plain_keys;
    plain_keys.reserve(test.num_plain_inputs);
    for (std::size_t i = 0; i < test.num_plain_inputs; ++i) {
        plain_keys.push_back(parsed_key(test.plain_pubkeys[i]));
    }
    auto summary_space = lent(sp::summary_workspace_size(taproot_keys.size(), plain_keys.size()));
    auto const summary =
        sp::make_prevouts_summary(std::span<std::uint8_t const, 36>(test.outpoint_smallest),
                                  taproot_keys, plain_keys, summary_space);
    BOOST_TEST(all_zero(summary_space));
    if (summary) {
        return *summary;
    }
    BOOST_TEST_EQ(subtest.num_found_output_pubkeys, 0U);
    auto const no_input = taproot_keys.empty() && plain_keys.empty();
    BOOST_TEST(summary.error() ==
               (no_input ? crypto::error::invalid_input_size : crypto::error::invalid_public_key));
    return std::nullopt;
}

// A found output is one of the case's, with its tweak, and the key pair of the spend secret
// plus the tweak signs as the case says and is the output's key.
void check_found(bip352_receive_subtest const& subtest, sp::found_output const& output) {
    auto const message = sha256_of("message");
    auto const aux = sha256_of("random auxiliary data");
    auto const spend_secret = subtest.spend_seckey;
    auto const expected_keys =
        std::span(subtest.found_output_pubkeys).first(subtest.num_found_output_pubkeys);
    auto const listed = std::ranges::find_if(
        expected_keys, [&](auto const& key) { return std::ranges::equal(output.output_key, key); });
    if (!BOOST_TEST(listed != expected_keys.end())) {
        return;
    }
    auto const at = static_cast<std::size_t>(listed - expected_keys.begin());
    BOOST_TEST(std::ranges::equal(output.spend_tweak.bytes(), subtest.found_seckey_tweaks[at]));
    auto const spend_tweaked = secp::seckey_tweak_add(spend_secret, output.spend_tweak);
    if (!BOOST_TEST(spend_tweaked.has_value())) {
        return;
    }
    auto const spending = keypair_of(spend_tweaked->bytes());
    auto const signature = spending.sign(crypto::schnorr, message, aux);
    if (BOOST_TEST(signature.has_value())) {
        BOOST_TEST(std::ranges::equal(*signature, subtest.found_signatures[at]));
    }
    auto const output_of_key = spending.xonly_public_key();
    if (BOOST_TEST(output_of_key.has_value())) {
        BOOST_TEST(*output_of_key == output.output_key);
    }
}

void receive_one(bip352_test_vector const& test, bip352_receive_subtest const& subtest,
                 receive_counts& counts) {
    auto const summary = summary_of(test, subtest);
    if (!summary) {
        ++counts.refused;
        return;
    }
    auto const scan_key = keypair_of(subtest.scan_seckey);
    auto const spend_key = public_of(keypair_of(subtest.spend_seckey));
    label_cache cache;
    for (std::size_t i = 0; i < subtest.num_labels; ++i) {
        auto const made = sp::create_label(scan_key, subtest.label_integers[i]);
        if (BOOST_TEST(made.has_value())) {
            cache.labels.push_back(*made);
        }
    }
    std::vector<xonly> outputs;
    outputs.reserve(subtest.num_to_scan_outputs);
    for (std::size_t i = 0; i < subtest.num_to_scan_outputs; ++i) {
        outputs.push_back(subtest.to_scan_outputs[i]);
    }
    std::vector<sp::found_output> found(outputs.size());
    auto scan_space = lent(sp::scan_workspace_size(outputs.size()));
    // A recipient with no labels scans with none, as a wallet does.
    auto const found_count =
        cache.labels.empty()
            ? sp::scan_outputs(scan_key, spend_key, *summary, outputs, found, scan_space)
            : sp::scan_outputs(scan_key, spend_key, *summary, outputs, found, scan_space, cache);
    BOOST_TEST(all_zero(scan_space));
    if (!BOOST_TEST(found_count.has_value())) {
        return;
    }
    ++counts.scanned;
    counts.found += static_cast<int>(*found_count);
    BOOST_TEST_EQ(*found_count, subtest.num_found_output_pubkeys);
    for (auto const& output : std::span(found).first(std::min(*found_count, found.size()))) {
        if (subtest.full_check != 0) {
            check_found(subtest, output);
        }
        // With no labels, nothing is found with one; with labels, a label is one the lookup
        // knows.
        BOOST_TEST(!output.label_point.has_value() ||
                   (subtest.num_labels != 0 && cache(*output.label_point).has_value()));
    }
    if (subtest.full_check != 0) {
        ++counts.full_checks;
    }
}

void receiving() {
    receive_counts counts;
    int subtests = 0;
    for (std::size_t case_index = 0; case_index < webcpp_test_bip352_vector_count(); ++case_index) {
        auto const& test = *webcpp_test_bip352_vector(case_index);
        for (std::size_t sub = 0; sub < test.num_receive_subtests; ++sub) {
            receive_one(test, test.receive_subtests[sub], counts);
            ++subtests;
        }
    }
    std::cout << "receiving: subtests=" << subtests << " scanned=" << counts.scanned
              << " refused=" << counts.refused << " full_checks=" << counts.full_checks
              << " found=" << counts.found << '\n';
    BOOST_TEST_EQ(subtests, 29);
    BOOST_TEST_EQ(counts.scanned + counts.refused, 29);
    BOOST_TEST_EQ(counts.refused, 2);
}

// Fixed keys for the refusals and round trips: a sender, a recipient's scan and spend keys.
scalar key_bytes(std::uint8_t last) {
    scalar out{};
    out[0] = 0x11;
    out[31] = last;
    return out;
}

// The recipient's side of the labelled round trip: the scan with the labels finds the output
// with the label it was sent to, the scan without them finds nothing, and the spend secret plus
// the tweak is the output's key.
void find_labelled(secp::keypair const& scan_key, secp::public_key const& spend_key,
                   sp::prevouts_summary const& summary, label_cache const& cache,
                   std::span<xonly const> outputs, sp::label const& sent_label) {
    std::vector<sp::found_output> found(1);
    auto scan_space = lent(sp::scan_workspace_size(1));
    auto const count =
        sp::scan_outputs(scan_key, spend_key, summary, outputs, found, scan_space, cache);
    if (!BOOST_TEST(count.has_value()) || !BOOST_TEST_EQ(*count, 1U)) {
        return;
    }
    BOOST_TEST(found[0].output_key == outputs[0]);
    BOOST_TEST(found[0].label_point == std::optional(sent_label.point));
    auto const tweaked = secp::seckey_tweak_add(key_bytes(3), found[0].spend_tweak);
    if (BOOST_TEST(tweaked.has_value())) {
        auto const output_key = keypair_of(tweaked->bytes()).xonly_public_key();
        BOOST_TEST(output_key.has_value() && *output_key == outputs[0]);
    }
    std::vector<sp::found_output> unlabelled_found(1);
    auto const unlabelled =
        sp::scan_outputs(scan_key, spend_key, summary, outputs, unlabelled_found, scan_space);
    BOOST_TEST(unlabelled.has_value() && *unlabelled == 0);
}

// A labelled address: the sender pays the labelled spend key, the recipient finds the output
// with the label it made, and the spend tweak spends it.
void labelled_round_trip() {
    auto const sender = keypair_of(key_bytes(1));
    auto const scan_key = keypair_of(key_bytes(2));
    auto const spend_key = public_of(keypair_of(key_bytes(3)));
    auto const change = sp::create_label(scan_key, 0);
    auto const other = sp::create_label(scan_key, 7);
    if (!BOOST_TEST(change.has_value()) || !BOOST_TEST(other.has_value())) {
        return;
    }
    BOOST_TEST(change->point != other->point);
    auto const labelled = sp::create_labeled_spend_key(spend_key, *other);
    if (!BOOST_TEST(labelled.has_value())) {
        return;
    }
    BOOST_TEST(!(*labelled == spend_key));
    sp::recipient const address{.scan_key = public_of(scan_key), .spend_key = *labelled};
    std::array<sp::recipient, 1> const recipients{address};
    std::array<std::uint8_t, sp::outpoint_size> const outpoint{1, 2, 3};
    std::array<secp::keypair const*, 1> const plain{&sender};
    std::array<xonly, 1> outputs{};
    auto space = lent(sp::send_workspace_size(1, 0, 1));
    BOOST_TEST(sp::create_outputs(recipients, outpoint, {}, plain, outputs, space).has_value());
    BOOST_TEST(all_zero(space));
    std::array<secp::public_key, 1> const sender_keys{public_of(sender)};
    auto summary_space = lent(sp::summary_workspace_size(0, 1));
    auto const summary = sp::make_prevouts_summary(outpoint, {}, sender_keys, summary_space);
    if (BOOST_TEST(summary.has_value())) {
        label_cache cache;
        cache.labels = {*change, *other};
        find_labelled(scan_key, spend_key, *summary, cache, outputs, *other);
    }
    // A label point that is not a point.
    sp::label broken = *other;
    broken.point.fill(0xff);
    broken.point[0] = 0x02;
    BOOST_TEST(sp::create_labeled_spend_key(spend_key, broken).error() ==
               crypto::error::invalid_point);
    // A label whose point is the spend key negated: the sum is the point at infinity.
    sp::label opposite = *other;
    opposite.point = secp::serialize_public_key(secp::pubkey_negate(spend_key).value());
    BOOST_TEST(sp::create_labeled_spend_key(spend_key, opposite).error() ==
               crypto::error::invalid_public_key);
}

// The keys of the refusals: a sender with a plain and a Taproot input, and a recipient paid
// twice.
struct refusal_keys {
    secp::keypair sender = keypair_of(key_bytes(1));
    secp::keypair second = keypair_of(key_bytes(4));
    secp::keypair scan_key = keypair_of(key_bytes(2));
    secp::public_key spend_key = public_of(keypair_of(key_bytes(3)));
    std::array<sp::recipient, 2> recipients{
        sp::recipient{.scan_key = public_of(scan_key), .spend_key = spend_key},
        sp::recipient{.scan_key = public_of(scan_key), .spend_key = spend_key},
    };
    std::array<std::uint8_t, sp::outpoint_size> outpoint{9};
    std::array<secp::keypair const*, 1> taproot{&second};
    std::array<secp::keypair const*, 1> plain{&sender};
    std::vector<std::byte> space;

    // A workspace of `size` bytes, filled with non-zero bytes.
    secp::workspace fresh(std::size_t size) {
        space = lent(size);
        return space;
    }

    // Whether the workspace is zero, but for the byte past a span one byte short.
    [[nodiscard]] bool wiped(std::size_t lent_size) const {
        return all_zero(std::span(space).first(lent_size));
    }
};

// Sending: no recipient, no input, outputs not one per recipient, a short workspace, a null
// pointer among the inputs and a moved-from key pair on either side.
void send_refusals(refusal_keys& keys) {
    std::array<xonly, 2> outputs{};
    auto const size = sp::send_workspace_size(2, 1, 1);
    auto const refused = [&](auto taproot, auto plain, std::span<xonly> into, std::size_t lent_size,
                             crypto::error expected) {
        auto const lent_space = keys.fresh(lent_size + 1).first(lent_size);
        auto const sent =
            sp::create_outputs(keys.recipients, keys.outpoint, taproot, plain, into, lent_space);
        BOOST_TEST(!sent.has_value() && sent.error() == expected);
        BOOST_TEST(keys.wiped(lent_size));
    };
    auto const too_few = crypto::error::invalid_input_size;
    BOOST_TEST(
        sp::create_outputs({}, keys.outpoint, keys.taproot, keys.plain, outputs, keys.fresh(size))
            .error() == too_few);
    BOOST_TEST(all_zero(keys.space));
    refused(std::span<secp::keypair const* const>{}, std::span<secp::keypair const* const>{},
            outputs, size, too_few);
    refused(keys.taproot, keys.plain, std::span(outputs).first(1), size, too_few);
    refused(keys.taproot, keys.plain, outputs, size - 1, too_few);
    refused(keys.taproot, keys.plain, outputs, 0, too_few);
    std::array<secp::keypair const*, 2> const with_null{&keys.sender, nullptr};
    auto const state = crypto::error::invalid_state;
    refused(with_null, keys.plain, outputs, sp::send_workspace_size(2, 2, 1), state);
    refused(keys.taproot, with_null, outputs, sp::send_workspace_size(2, 1, 2), state);
    auto moved = keypair_of(key_bytes(5));
    auto const taker = std::move(moved);
    // NOLINTBEGIN(bugprone-use-after-move): the moved-from key pair is what is refused
    std::array<secp::keypair const*, 1> const empty_pair{&moved};
    refused(empty_pair, keys.plain, outputs, size, state);
    refused(keys.taproot, empty_pair, outputs, size, state);
    BOOST_TEST(sp::create_label(moved, 0).error() == state);
    // NOLINTEND(bugprone-use-after-move)
}

// Inputs of one kind only, the other side an emptied vector whose data() is not null:
// libsecp256k1 is given nullptr for it, and nothing aborts.
void one_kind_of_input(refusal_keys& keys) {
    std::array<xonly, 2> outputs{};
    std::vector<secp::keypair const*> emptied;
    emptied.reserve(4);
    std::vector<xonly> emptied_keys;
    emptied_keys.reserve(4);
    std::vector<secp::public_key> emptied_points;
    emptied_points.reserve(4);
    BOOST_TEST(sp::create_outputs(keys.recipients, keys.outpoint, keys.taproot, emptied, outputs,
                                  keys.fresh(sp::send_workspace_size(2, 1, 0)))
                   .has_value());
    BOOST_TEST(all_zero(keys.space));
    BOOST_TEST(sp::create_outputs(keys.recipients, keys.outpoint, emptied, keys.plain, outputs,
                                  keys.fresh(sp::send_workspace_size(2, 0, 1)))
                   .has_value());
    BOOST_TEST(all_zero(keys.space));
    auto const taproot_key = keys.second.xonly_public_key();
    if (BOOST_TEST(taproot_key.has_value())) {
        std::array<xonly, 1> const taproot_keys{*taproot_key};
        BOOST_TEST(sp::make_prevouts_summary(keys.outpoint, taproot_keys, emptied_points,
                                             keys.fresh(sp::summary_workspace_size(1, 0)))
                       .has_value());
        BOOST_TEST(all_zero(keys.space));
    }
    std::array<secp::public_key, 1> const plain_keys{public_of(keys.sender)};
    BOOST_TEST(sp::make_prevouts_summary(keys.outpoint, emptied_keys, plain_keys,
                                         keys.fresh(sp::summary_workspace_size(0, 1)))
                   .has_value());
    BOOST_TEST(all_zero(keys.space));
}

// An x-only key that is not one: its x is not below the field's prime.
xonly not_a_key() {
    xonly out{};
    out.fill(0xff);
    return out;
}

// The summary: no input key, a short workspace, a Taproot key that does not parse, keys that
// sum to infinity.
void summary_refusals(refusal_keys& keys) {
    std::array<secp::public_key, 1> const plain_keys{public_of(keys.sender)};
    auto const size = sp::summary_workspace_size(0, 1);
    BOOST_TEST(sp::make_prevouts_summary(keys.outpoint, {}, {}, keys.fresh(size)).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(keys.space));
    BOOST_TEST(
        sp::make_prevouts_summary(keys.outpoint, {}, plain_keys, keys.fresh(size).first(size - 1))
            .error() == crypto::error::invalid_input_size);
    BOOST_TEST(keys.wiped(size - 1));
    std::array<xonly, 1> const bad_keys{not_a_key()};
    BOOST_TEST(sp::make_prevouts_summary(keys.outpoint, bad_keys, {},
                                         keys.fresh(sp::summary_workspace_size(1, 0)))
                   .error() == crypto::error::invalid_public_key);
    BOOST_TEST(all_zero(keys.space));
    std::array<secp::public_key, 2> const opposite{
        public_of(keys.sender),
        secp::pubkey_negate(public_of(keys.sender)).value(),
    };
    BOOST_TEST(sp::make_prevouts_summary(keys.outpoint, {}, opposite,
                                         keys.fresh(sp::summary_workspace_size(0, 2)))
                   .error() == crypto::error::invalid_public_key);
    BOOST_TEST(all_zero(keys.space));
}

// The scan: no output key, `found` shorter than the outputs, a short workspace, an output key
// that does not parse, a moved-from scan key pair.
void scan_refusals(refusal_keys& keys) {
    std::array<secp::public_key, 1> const plain_keys{public_of(keys.sender)};
    auto const summary = sp::make_prevouts_summary(keys.outpoint, {}, plain_keys,
                                                   keys.fresh(sp::summary_workspace_size(0, 1)));
    if (!BOOST_TEST(summary.has_value())) {
        return;
    }
    std::array<xonly, 2> outputs{};
    std::array<sp::found_output, 2> found{};
    auto const size = sp::scan_workspace_size(2);
    auto const refused = [&](secp::keypair const& scan_key, std::span<xonly const> output_keys,
                             std::span<sp::found_output> into, std::size_t lent_size,
                             crypto::error expected) {
        auto const lent_space = keys.fresh(lent_size + 1).first(lent_size);
        auto const scanned =
            sp::scan_outputs(scan_key, keys.spend_key, *summary, output_keys, into, lent_space);
        BOOST_TEST(!scanned.has_value() && scanned.error() == expected);
        BOOST_TEST(keys.wiped(lent_size));
    };
    auto const too_few = crypto::error::invalid_input_size;
    refused(keys.scan_key, {}, found, size, too_few);
    refused(keys.scan_key, outputs, std::span(found).first(1), size, too_few);
    refused(keys.scan_key, outputs, found, size - 1, too_few);
    std::array<xonly, 2> const with_bad{outputs[0], not_a_key()};
    refused(keys.scan_key, with_bad, found, size, crypto::error::invalid_public_key);
    auto moved = keypair_of(key_bytes(5));
    auto const taker = std::move(moved);
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair is what is refused
    refused(moved, outputs, found, size, crypto::error::invalid_state);
}

// The group limit, counted by webcpp only after libsecp256k1 refuses: 2324 recipients in two
// groups of 1162 with inputs that sum to zero stay invalid_secret_key (no group is over the
// limit), and 2325 recipients whose one group of 2324 starts after another key's recipient are
// invalid_input_size.
void group_limits(refusal_keys& keys) {
    auto const negated = secp::seckey_negate(key_bytes(1));
    if (!BOOST_TEST(negated.has_value())) {
        return;
    }
    auto const opposite = keypair_of(negated->bytes());
    std::array<secp::keypair const*, 2> const zero_sum{&keys.sender, &opposite};
    auto const other_scan = public_of(keys.second);
    std::vector<sp::recipient> two_groups;
    two_groups.reserve(sp::group_limit + 1);
    for (std::size_t index = 0; index < sp::group_limit + 1; ++index) {
        two_groups.push_back(sp::recipient{
            .scan_key = index % 2 == 0 ? public_of(keys.scan_key) : other_scan,
            .spend_key = keys.spend_key,
        });
    }
    std::vector<xonly> outputs(two_groups.size());
    auto const size = sp::send_workspace_size(two_groups.size(), 0, 2);
    BOOST_TEST(
        sp::create_outputs(two_groups, keys.outpoint, {}, zero_sum, outputs, keys.fresh(size))
            .error() == crypto::error::invalid_secret_key);
    BOOST_TEST(all_zero(keys.space));
    std::vector<sp::recipient> one_over{
        sp::recipient{.scan_key = other_scan, .spend_key = keys.spend_key},
    };
    one_over.insert(
        one_over.end(), sp::group_limit + 1,
        sp::recipient{.scan_key = public_of(keys.scan_key), .spend_key = keys.spend_key});
    outputs.resize(one_over.size());
    BOOST_TEST(sp::create_outputs(one_over, keys.outpoint, {}, keys.plain, outputs,
                                  keys.fresh(sp::send_workspace_size(one_over.size(), 0, 1)))
                   .error() == crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(keys.space));
}

void refusals() {
    refusal_keys keys;
    group_limits(keys);
    send_refusals(keys);
    one_kind_of_input(keys);
    summary_refusals(keys);
    scan_refusals(keys);
    // An empty key pair answers invalid_state everywhere, silent payments included.
    auto emptied_pair = keypair_of(key_bytes(6));
    auto const keeper = std::move(emptied_pair);
    webcpp::test::expect_empty_keypair(emptied_pair);  // NOLINT(bugprone-use-after-move)
}

// Two payments to one address from one wallet share no output key: the outpoint differs.
void unlinkable() {
    auto const sender = keypair_of(key_bytes(1));
    auto const scan_key = keypair_of(key_bytes(2));
    auto const spend_key = public_of(keypair_of(key_bytes(3)));
    sp::recipient const address{.scan_key = public_of(scan_key), .spend_key = spend_key};
    std::array<sp::recipient, 1> const recipients{address};
    std::array<secp::keypair const*, 1> const plain{&sender};
    std::array<xonly, 1> first{};
    std::array<xonly, 1> second{};
    std::array<std::uint8_t, sp::outpoint_size> outpoint{1};
    auto space = lent(sp::send_workspace_size(1, 0, 1));
    BOOST_TEST(sp::create_outputs(recipients, outpoint, {}, plain, first, space).has_value());
    outpoint[0] = 2;
    BOOST_TEST(sp::create_outputs(recipients, outpoint, {}, plain, second, space).has_value());
    BOOST_TEST(first[0] != second[0]);
}

}  // namespace

int main() {
    layout();
    sending();
    receiving();
    labelled_round_trip();
    refusals();
    unlinkable();
    return webcpp::test::exit_status(boost::report_errors());
}
