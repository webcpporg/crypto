// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1's silent payments on libsecp256k1 (BIP 352): the sender's outputs to a reusable
 address of two keys, scan and spend, the recipient's labels, and the recipient's scan of a
 transaction's outputs, which finds its payments and the tweaks that spend them.
 Addresses, transactions and the choice of eligible inputs are a domain library's.

 @see "Silent payments", in the guide's secp256k1 chapter.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_SILENT_PAYMENTS_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_SILENT_PAYMENTS_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>

namespace webcpp::crypto::detail {

/**
 * The refusal of a backend other than libsecp256k1 by the family
 * `families::secp256k1_silent_payments`: the functions of `curves/secp256k1/silent_payments.hpp`.
 *
 * @tparam Backend The backend named.
 */
template <class Backend>
struct secp256k1_refusal<families::secp256k1_silent_payments, Backend, false> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECP256K1_SILENT_PAYMENTS(Backend);
};

/**
 * What `scan_outputs` gives libsecp256k1 as its label context: the caller's lookup, and the
 * function that calls it, so that the C callback reaches a C++ callable of any type.
 */
struct secp256k1_label_context {
    /** The caller's lookup, which outlives the scan. */
    void const* lookup_object;
    /** Calls the lookup with a candidate label's 33 bytes: its tweak's 32 bytes, or null. */
    unsigned char const* (*call_lookup)(void const*, unsigned char const*) noexcept;
};

/**
 * Calls a lookup of type `LabelLookup` with a candidate label.
 *
 * @tparam LabelLookup The lookup's type, which satisfies `label_lookup`.
 * @param lookup_object The lookup.
 * @param label_bytes The candidate label's 33 bytes.
 * @return Its tweak's 32 bytes, which stay valid until the next call; null when it is no label.
 */
template <class LabelLookup>
[[nodiscard]] unsigned char const* secp256k1_call_label_lookup(
    void const* lookup_object, unsigned char const* label_bytes) noexcept {
    // The concept's type, which any result the concept admits converts to.
    std::optional<std::span<std::uint8_t const, 32>> const found_tweak =
        (*static_cast<LabelLookup const*>(lookup_object))(
            std::span<std::uint8_t const, 33>(label_bytes, 33));
    return found_tweak ? found_tweak->data() : nullptr;
}

extern "C" {

/**
 * libsecp256k1's label lookup callback, which reaches the caller's lookup through the
 * `secp256k1_label_context` it is given. C linkage, as libsecp256k1's function pointer type has.
 *
 * @param label_bytes The candidate label's 33 bytes.
 * @param label_context The `secp256k1_label_context`.
 * @return The label's tweak, or null.
 */
inline unsigned char const* webcpp_crypto_detail_secp256k1_label_lookup(
    unsigned char const* label_bytes, void const* label_context) noexcept {
    auto const* const context = static_cast<secp256k1_label_context const*>(label_context);
    return context->call_lookup(context->lookup_object, label_bytes);
}

}  // extern "C"

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1::silent_payments {

/** The size of a transaction's smallest outpoint, serialised: 36 bytes. */
inline constexpr std::size_t outpoint_size = 36;

/** The most outputs one scan key's group may hold (BIP 352's limit). */
inline constexpr std::size_t group_limit = SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT;

/**
 * A recipient as the sender reads it from the address: its scan and spend keys (decoding
 * the address is a domain library's).
 */
struct recipient {
    /** The scan key, whose secret the recipient scans with. */
    public_key scan_key;
    /** The spend key, labelled or not, which each output tweaks. */
    public_key spend_key;
};

/** A label (`secp256k1_silentpayments_label`, serialised) and its tweak. */
struct label {
    /** The label's point, SEC1 compressed: the tweak times the generator. */
    std::array<std::uint8_t, 33> point;
    /** The label's tweak, which the scan adds to an output found with this label. */
    std::array<std::uint8_t, 32> tweak;
};

/**
 * An output the recipient found: its x-only key, the tweak that spends it (added to the
 * spend secret key with `seckey_tweak_add`), and the label it was sent to, if any.
 */
struct found_output {
    /** The output's x-only key. */
    std::array<std::uint8_t, 32> output_key{};
    /** The spend secret key plus this tweak is the output's secret key. */
    secret<32> spend_tweak;
    /** The label the output was sent to, or none for the address without a label. */
    std::optional<std::array<std::uint8_t, 33>> label_point;
};

/**
 * The prevouts' summary a recipient scans with: the sum of the eligible inputs' public keys and
 * the input hash (libsecp256k1's prevouts_summary, 101 bytes), public, copied freely, made only by
 * `make_prevouts_summary`.
 */
class prevouts_summary {
private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    prevouts_summary() noexcept = default;

    secp256k1_silentpayments_prevouts_summary native_value_{};
};

/**
 * Whether `LabelLookup` can look up a label for `scan_outputs`.
 *
 * Called with a candidate label's 33 bytes, it returns the label's 32-byte tweak or
 * `std::nullopt`, and is noexcept, since libsecp256k1's C frames are between the scan and the
 * lookup. The tweak's bytes stay valid until the lookup is called again.
 *
 * @tparam LabelLookup The lookup's type.
 */
template <class LabelLookup>
concept label_lookup =
    std::is_nothrow_invocable_r_v<std::optional<std::span<std::uint8_t const, 32>>,
                                  LabelLookup const&, std::span<std::uint8_t const, 33>>;

/** The lookup of a recipient with no labels: it knows none. */
struct no_labels {
    /**
     * Finds no label.
     *
     * @return `std::nullopt`.
     */
    [[nodiscard]] std::optional<std::span<std::uint8_t const, 32>> operator()(
        std::span<std::uint8_t const, 33> /*candidate_label*/) const noexcept {
        return std::nullopt;
    }
};

/**
 * The workspace `create_outputs` needs, in bytes.
 *
 * @param recipient_count The number of recipients.
 * @param taproot_input_count The number of Taproot inputs.
 * @param plain_input_count The number of other eligible inputs.
 * @return The recipients' structs and their pointers, the outputs and their pointers, the
 * Taproot key pairs' pointers, the plain inputs' secrets and their pointers, and one
 * `alignof(std::max_align_t)` of padding per array.
 */
[[nodiscard]] constexpr std::size_t send_workspace_size(std::size_t recipient_count,
                                                        std::size_t taproot_input_count,
                                                        std::size_t plain_input_count) noexcept {
    return (recipient_count * (sizeof(secp256k1_silentpayments_recipient) + sizeof(void*) +
                               sizeof(secp256k1_xonly_pubkey) + sizeof(void*))) +
           (taproot_input_count * sizeof(void*)) + (plain_input_count * (32 + sizeof(void*))) +
           (7 * alignof(std::max_align_t));
}

/**
 * The workspace `make_prevouts_summary` needs, in bytes.
 *
 * @param taproot_input_count The number of Taproot inputs' x-only keys.
 * @param plain_input_count The number of other eligible inputs' keys.
 * @return The parsed x-only keys and their pointers, the plain keys' pointers, and one
 * `alignof(std::max_align_t)` of padding per array.
 */
[[nodiscard]] constexpr std::size_t summary_workspace_size(std::size_t taproot_input_count,
                                                           std::size_t plain_input_count) noexcept {
    return (taproot_input_count * (sizeof(secp256k1_xonly_pubkey) + sizeof(void*))) +
           (plain_input_count * sizeof(void*)) + (3 * alignof(std::max_align_t));
}

/**
 * The workspace `scan_outputs` needs, in bytes.
 *
 * @param output_count The number of the transaction's outputs.
 * @return The parsed outputs and their pointers, libsecp256k1's found outputs and their
 * pointers, and one `alignof(std::max_align_t)` of padding per array.
 */
[[nodiscard]] constexpr std::size_t scan_workspace_size(std::size_t output_count) noexcept {
    return (output_count * (sizeof(secp256k1_xonly_pubkey) + sizeof(void*) +
                            sizeof(secp256k1_silentpayments_found_output) + sizeof(void*))) +
           (4 * alignof(std::max_align_t));
}

}  // namespace webcpp::crypto::curves::secp256k1::silent_payments

namespace webcpp::crypto::detail {

/**
 * Whether more than `group_limit` recipients share one scan key, which libsecp256k1 refuses as
 * it refuses a sum of zero. The recipients' pointers are sorted in place by scan key, as
 * libsecp256k1 sorts them, and each run of one key is counted: O(n log n), nothing allocated.
 *
 * @param recipient_pointers The recipients' pointers, in the workspace.
 * @return Whether a group is over the limit.
 */
[[nodiscard]] inline bool secp256k1_over_group_limit(
    std::span<secp256k1_silentpayments_recipient const*> recipient_pointers) noexcept {
    auto const scan_key_order = [](secp256k1_silentpayments_recipient const* left_recipient,
                                   secp256k1_silentpayments_recipient const* right_recipient) {
        return secp256k1_ec_pubkey_cmp(secp256k1_context_static, &left_recipient->scan_pubkey,
                                       &right_recipient->scan_pubkey) < 0;
    };
    std::ranges::sort(recipient_pointers, scan_key_order);
    std::size_t group_size = 0;
    for (std::size_t index = 0; index < recipient_pointers.size(); ++index) {
        bool const same_group =
            index != 0 && !scan_key_order(recipient_pointers[index - 1], recipient_pointers[index]);
        group_size = same_group ? group_size + 1 : 1;
        if (group_size > curves::secp256k1::silent_payments::group_limit) {
            return true;
        }
    }
    return false;
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1::silent_payments {

/**
 * The sender's outputs (`secp256k1_silentpayments_sender_create_outputs`): one x-only key
 * per recipient, in the recipients' order, from the secret keys of the transaction's eligible
 * inputs, Taproot inputs (their keys negated for an odd y, as BIP 352 says) apart from the
 * others, and the smallest outpoint, which the caller determines.
 *
 * The context is the first Taproot input's key pair's, else the first plain input's.
 *
 * Tip: every output made must be in the transaction, and the outpoint must be the transaction's
 * smallest, or the recipient never finds the payment.
 *
 * @tparam Backend The key pairs' backend, `backends::secp256k1`.
 * @param recipients The recipients, at least one; a recipient paid twice is listed twice.
 * @param smallest_outpoint The smallest outpoint of all the transaction's inputs, serialised.
 * @param taproot_inputs The key pairs of the Taproot inputs.
 * @param plain_inputs The key pairs of the other eligible inputs.
 * @param output_keys One per recipient, where the outputs' x-only keys go.
 * @param pointer_space At least `send_workspace_size(recipients.size(), taproot_inputs.size(),
 * plain_inputs.size())` bytes; zero when the function returns, whatever it returns.
 * @return Nothing; `invalid_input_size` (no recipient, no input at all, outputs not one per
 * recipient, a short workspace, more than `group_limit` recipients sharing a scan key, which
 * webcpp counts only when there are more recipients than that); `invalid_state` (a moved-from
 * key pair, or a null pointer among the inputs); `invalid_secret_key` when libsecp256k1
 * refuses: the inputs' keys sum to zero, or a recipient's spend key gives no output, which only
 * a key chosen against the sender can.
 */
template <class Backend = default_backend_t<families::secp256k1_silent_payments>>
[[nodiscard]] boost::system::result<void> create_outputs(
    std::span<recipient const> recipients,
    std::span<std::uint8_t const, outpoint_size> smallest_outpoint,
    std::span<std::type_identity_t<basic_keypair<Backend>> const* const> taproot_inputs,
    std::span<std::type_identity_t<basic_keypair<Backend>> const* const> plain_inputs,
    std::span<std::array<std::uint8_t, 32>> output_keys, workspace pointer_space) noexcept {
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_silent_payments,
                                                         Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // The carver first: it wipes the workspace, the plain inputs' secrets in it, on every return.
    webcpp::crypto::detail::secp256k1_workspace carver(pointer_space);
    std::size_t const recipient_count = recipients.size();
    std::size_t const taproot_count = taproot_inputs.size();
    std::size_t const plain_count = plain_inputs.size();
    // libsecp256k1 checks the counts with ARG_CHECK, whose callback aborts: refused first here.
    if (recipient_count == 0 || (taproot_count == 0 && plain_count == 0) ||
        output_keys.size() != recipient_count ||
        pointer_space.size() < send_workspace_size(recipient_count, taproot_count, plain_count)) {
        return error::invalid_input_size;
    }
    using access = webcpp::crypto::detail::secp256k1_access;
    // Every pointer is checked before any is used, as libsecp256k1's ARG_CHECKs would.
    auto const usable = [](basic_keypair<Backend> const* input) {
        return input != nullptr && access::keyed(*input);
    };
    if (!std::ranges::all_of(taproot_inputs, usable) ||
        !std::ranges::all_of(plain_inputs, usable)) {
        return error::invalid_state;
    }
    auto* const recipient_values = carver.take<secp256k1_silentpayments_recipient>(recipient_count);
    auto* const recipient_pointers =
        carver.take<secp256k1_silentpayments_recipient const*>(recipient_count);
    auto* const output_values = carver.take<secp256k1_xonly_pubkey>(recipient_count);
    auto* const output_pointers = carver.take<secp256k1_xonly_pubkey*>(recipient_count);
    // Arrays of no elements are nullptr, as libsecp256k1 requires of a side with no input.
    auto* const taproot_pointers = carver.take<secp256k1_keypair const*>(taproot_count);
    auto* const plain_secrets = carver.take<std::array<unsigned char, 32>>(plain_count);
    auto* const plain_pointers = carver.take<unsigned char const*>(plain_count);
    if (recipient_values == nullptr || recipient_pointers == nullptr || output_values == nullptr ||
        output_pointers == nullptr || (taproot_count != 0 && taproot_pointers == nullptr) ||
        (plain_count != 0 && (plain_secrets == nullptr || plain_pointers == nullptr))) {
        return error::invalid_input_size;
    }
    for (std::size_t index = 0; index < recipient_count; ++index) {
        recipient_values[index] = secp256k1_silentpayments_recipient{
            .scan_pubkey = access::point(recipients[index].scan_key),
            .spend_pubkey = access::point(recipients[index].spend_key),
            .index = index,
        };
        recipient_pointers[index] = &recipient_values[index];
        output_values[index] = secp256k1_xonly_pubkey{};
        output_pointers[index] = &output_values[index];
    }
    for (std::size_t index = 0; index < taproot_count; ++index) {
        taproot_pointers[index] = &access::pair(*taproot_inputs[index]);
    }
    for (std::size_t index = 0; index < plain_count; ++index) {
        secp256k1_keypair_sec(access::context(*plain_inputs[index]), plain_secrets[index].data(),
                              &access::pair(*plain_inputs[index]));
        plain_pointers[index] = plain_secrets[index].data();
    }
    auto const* const signer = taproot_count != 0 ? taproot_inputs[0] : plain_inputs[0];
    if (!webcpp::crypto::detail::secp256k1_accepted(secp256k1_silentpayments_sender_create_outputs(
            access::context(*signer), output_pointers, recipient_pointers, recipient_count,
            smallest_outpoint.data(), taproot_pointers, taproot_count, plain_pointers,
            plain_count))) {
        if (recipient_count > group_limit && webcpp::crypto::detail::secp256k1_over_group_limit(
                                                 std::span(recipient_pointers, recipient_count))) {
            return error::invalid_input_size;
        }
        return error::invalid_secret_key;
    }
    for (std::size_t index = 0; index < recipient_count; ++index) {
        // A made output always serialises: libsecp256k1 returns 1.
        static_cast<void>(secp256k1_xonly_pubkey_serialize(
            secp256k1_context_static, output_keys[index].data(), &output_values[index]));
    }
    return {};
}

/**
 * The `m`-th label of a scan key (`secp256k1_silentpayments_recipient_label_create`); 0 is
 * BIP 352's change label.
 *
 * Tip: many labels may slow scanning down in some wallets, light clients among them; create the
 * change label alone, and hand out no labelled address and never the change label.
 *
 * @tparam Backend The key pair's backend, `backends::secp256k1`.
 * @param scan_key The scan key pair, whose context makes the label.
 * @param label_number The label's integer m.
 * @return The label; `invalid_state` moved from; `backend_failure` should the label's hash not
 * be a valid scalar, which happens with negligible probability.
 */
template <class Backend>
[[nodiscard]] boost::system::result<label> create_label(basic_keypair<Backend> const& scan_key,
                                                        std::uint32_t label_number) noexcept {
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_silent_payments,
                                                         Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    using access = webcpp::crypto::detail::secp256k1_access;
    if (!access::keyed(scan_key)) {
        return error::invalid_state;
    }
    webcpp::crypto::detail::secp256k1_secret scan_secret;
    secp256k1_keypair_sec(access::context(scan_key), scan_secret.bytes.data(),
                          &access::pair(scan_key));
    secp256k1_silentpayments_label made_label{};
    label created_label{};
    if (!webcpp::crypto::detail::secp256k1_accepted(secp256k1_silentpayments_recipient_label_create(
            access::context(scan_key), &made_label, created_label.tweak.data(),
            scan_secret.bytes.data(), label_number))) {
        return error::backend_failure;
    }
    // The label's point is public, the labelled address's part; libsecp256k1 made it from the
    // scan key's secret, so it is marked public here (detail/declassify.hpp). A made label always
    // serialises: libsecp256k1 returns 1.
    WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&made_label, sizeof made_label);
    static_cast<void>(secp256k1_silentpayments_recipient_label_serialize(
        secp256k1_context_static, created_label.point.data(), &made_label));
    return created_label;
}

/**
 * The spend key of a labelled address (`..._create_labeled_spend_pubkey`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param spend_key The recipient's spend key, without a label.
 * @param address_label The label, from `create_label`.
 * @return The labelled spend key; `invalid_point` for a label point that is not a point;
 * `invalid_public_key` when the key and the label sum to infinity.
 */
template <class Backend = default_backend_t<families::secp256k1_silent_payments>>
[[nodiscard]] boost::system::result<public_key> create_labeled_spend_key(
    public_key const& spend_key, label const& address_label) noexcept {
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_silent_payments,
                                                         Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    secp256k1_silentpayments_label parsed_label{};
    if (secp256k1_silentpayments_recipient_label_parse(secp256k1_context_static, &parsed_label,
                                                       address_label.point.data()) == 0) {
        return error::invalid_point;
    }
    public_key labeled_key = access::make_public_key();
    if (secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
            secp256k1_context_static, &access::point(labeled_key), &access::point(spend_key),
            &parsed_label) == 0) {
        return error::invalid_public_key;
    }
    return labeled_key;
}

/**
 * The prevouts' summary (`..._recipient_prevouts_summary_create`) from the eligible inputs'
 * public keys.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param smallest_outpoint The smallest outpoint of all the transaction's inputs, serialised.
 * @param taproot_input_keys The Taproot inputs' x-only keys.
 * @param plain_input_keys The other eligible inputs' keys.
 * @param pointer_space At least `summary_workspace_size(taproot_input_keys.size(),
 * plain_input_keys.size())` bytes; zero when the function returns, whatever it returns.
 * @return The summary; `invalid_input_size` for no input key at all or a short workspace (an
 * `ARG_CHECK` in libsecp256k1); `invalid_public_key` when they sum to infinity or a Taproot
 * key does not parse (not a silent payment).
 */
template <class Backend = default_backend_t<families::secp256k1_silent_payments>>
[[nodiscard]] boost::system::result<prevouts_summary> make_prevouts_summary(
    std::span<std::uint8_t const, outpoint_size> smallest_outpoint,
    std::span<std::array<std::uint8_t, 32> const> taproot_input_keys,
    std::span<public_key const> plain_input_keys, workspace pointer_space) noexcept {
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_silent_payments,
                                                         Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // The carver first: it wipes the workspace on every return, a refusal's included.
    webcpp::crypto::detail::secp256k1_workspace carver(pointer_space);
    std::size_t const taproot_count = taproot_input_keys.size();
    std::size_t const plain_count = plain_input_keys.size();
    // libsecp256k1 checks the counts with ARG_CHECK, whose callback aborts: refused first here.
    if ((taproot_count == 0 && plain_count == 0) ||
        pointer_space.size() < summary_workspace_size(taproot_count, plain_count)) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    // Arrays of no elements are nullptr, as libsecp256k1 requires of a side with no input.
    auto* const xonly_values = carver.take<secp256k1_xonly_pubkey>(taproot_count);
    auto* const xonly_pointers = carver.take<secp256k1_xonly_pubkey const*>(taproot_count);
    auto* const plain_pointers = carver.take<secp256k1_pubkey const*>(plain_count);
    if ((taproot_count != 0 && (xonly_values == nullptr || xonly_pointers == nullptr)) ||
        (plain_count != 0 && plain_pointers == nullptr)) {
        return error::invalid_input_size;
    }
    for (std::size_t index = 0; index < taproot_count; ++index) {
        if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &xonly_values[index],
                                         taproot_input_keys[index].data()) == 0) {
            return error::invalid_public_key;
        }
        xonly_pointers[index] = &xonly_values[index];
    }
    for (std::size_t index = 0; index < plain_count; ++index) {
        plain_pointers[index] = &access::point(plain_input_keys[index]);
    }
    auto summary = access::make_opaque<prevouts_summary>();
    if (secp256k1_silentpayments_recipient_prevouts_summary_create(
            secp256k1_context_static, &access::native(summary), smallest_outpoint.data(),
            xonly_pointers, taproot_count, plain_pointers, plain_count) == 0) {
        return error::invalid_public_key;
    }
    return summary;
}

/**
 * Scans a transaction's x-only outputs (`..._recipient_scan_outputs`) with the scan key pair
 * and the unlabelled spend key; `label_lookup` is called with a candidate label's 33 bytes
 * and returns its tweak or `std::nullopt`, noexcept (no labels: the default).
 *
 * Tip: a scan costs one ECDH per transaction, labels or not, which a light client must plan
 * for.
 *
 * @tparam Backend The key pair's backend, `backends::secp256k1`.
 * @tparam LabelLookup The lookup's type, `no_labels` by default.
 * @param scan_key The scan key pair.
 * @param spend_key The spend key, without a label.
 * @param summary The transaction's prevouts' summary.
 * @param output_keys The transaction's x-only outputs, in their order.
 * @param found Where the found outputs go, at least as many entries as outputs.
 * @param pointer_space At least `scan_workspace_size(output_keys.size())` bytes; zero when the
 * function returns, whatever it returns.
 * @param label_lookup The lookup of the recipient's labels.
 * @return The number of outputs found, written to the front of `found` (at least as many
 * entries as outputs); `invalid_input_size` (no output key, `found` shorter than the outputs,
 * a short workspace); `invalid_state`; `invalid_public_key` (an output that is not an x-only
 * key); `backend_failure` should a hash not be a valid scalar, which happens with negligible
 * probability.
 */
template <class Backend, label_lookup LabelLookup = no_labels>
[[nodiscard]] boost::system::result<std::size_t> scan_outputs(
    basic_keypair<Backend> const& scan_key, public_key const& spend_key,
    prevouts_summary const& summary, std::span<std::array<std::uint8_t, 32> const> output_keys,
    std::span<found_output> found, workspace pointer_space,
    LabelLookup const& label_lookup = {}) noexcept {
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_silent_payments,
                                                         Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // The carver first: it wipes the workspace, the found tweaks in it, on every return.
    webcpp::crypto::detail::secp256k1_workspace carver(pointer_space);
    std::size_t const output_count = output_keys.size();
    // libsecp256k1 checks the count with ARG_CHECK, whose callback aborts: refused first here.
    if (output_count == 0 || found.size() < output_count ||
        pointer_space.size() < scan_workspace_size(output_count)) {
        return error::invalid_input_size;
    }
    using access = webcpp::crypto::detail::secp256k1_access;
    if (!access::keyed(scan_key)) {
        return error::invalid_state;
    }
    secp256k1_selftest();
    auto* const output_values = carver.take<secp256k1_xonly_pubkey>(output_count);
    auto* const output_pointers = carver.take<secp256k1_xonly_pubkey const*>(output_count);
    auto* const found_values = carver.take<secp256k1_silentpayments_found_output>(output_count);
    auto* const found_pointers = carver.take<secp256k1_silentpayments_found_output*>(output_count);
    if (output_values == nullptr || output_pointers == nullptr || found_values == nullptr ||
        found_pointers == nullptr) {
        return error::invalid_input_size;
    }
    for (std::size_t index = 0; index < output_count; ++index) {
        if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &output_values[index],
                                         output_keys[index].data()) == 0) {
            return error::invalid_public_key;
        }
        output_pointers[index] = &output_values[index];
        found_values[index] = secp256k1_silentpayments_found_output{};
        found_pointers[index] = &found_values[index];
    }
    webcpp::crypto::detail::secp256k1_secret scan_secret;
    secp256k1_keypair_sec(access::context(scan_key), scan_secret.bytes.data(),
                          &access::pair(scan_key));
    std::uint32_t found_count = 0;
    // The scan runs on the scan key pair's context, as a key pair's other functions do, so that
    // libsecp256k1 marks its public values public under the constant-time checkers.
    int scan_status = 0;
    if constexpr (std::is_same_v<LabelLookup, no_labels>) {
        scan_status = secp256k1_silentpayments_recipient_scan_outputs(
            access::context(scan_key), found_pointers, &found_count, output_pointers, output_count,
            scan_secret.bytes.data(), &access::native(summary), &access::point(spend_key), nullptr,
            nullptr);
    } else {
        webcpp::crypto::detail::secp256k1_label_context const lookup_context{
            .lookup_object = &label_lookup,
            .call_lookup = &webcpp::crypto::detail::secp256k1_call_label_lookup<LabelLookup>,
        };
        scan_status = secp256k1_silentpayments_recipient_scan_outputs(
            access::context(scan_key), found_pointers, &found_count, output_pointers, output_count,
            scan_secret.bytes.data(), &access::native(summary), &access::point(spend_key),
            &webcpp::crypto::detail::webcpp_crypto_detail_secp256k1_label_lookup, &lookup_context);
    }
    if (!webcpp::crypto::detail::secp256k1_accepted(scan_status)) {
        return error::backend_failure;
    }
    for (std::size_t index = 0; index < found_count; ++index) {
        auto const& found_value = *found_pointers[index];
        auto& found_entry = found[index];
        // A found output and its label always serialise: libsecp256k1 returns 1.
        static_cast<void>(secp256k1_xonly_pubkey_serialize(
            secp256k1_context_static, found_entry.output_key.data(), &found_value.output));
        std::ranges::copy(found_value.tweak, found_entry.spend_tweak.writable().begin());
        found_entry.label_point.reset();
        if (found_value.found_with_label != 0) {
            std::array<std::uint8_t, 33> label_bytes{};
            static_cast<void>(secp256k1_silentpayments_recipient_label_serialize(
                secp256k1_context_static, label_bytes.data(), &found_value.label));
            found_entry.label_point = label_bytes;
        }
    }
    return std::size_t{found_count};
}

}  // namespace webcpp::crypto::curves::secp256k1::silent_payments

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_SILENT_PAYMENTS_HPP
