// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A guarded function of hash inside a guarded function of crypto, through secure's one guard
// (webcpp::secure::timing_guard, which both libraries hold) and its one seam: a stand-in backend's
// seal, run inside basic_chacha20_poly1305::seal's guard, derives a key with webcpp::hash::hkdf,
// which holds its own. The seam records crypto's guard first and hash's second; crypto's count,
// filtered by include/webcpp/crypto/, rises by one and the count of every guard by two. DIT is set
// inside both: hkdf's HMAC runs over dit_probe, a SHA-256 whose every update, inside hash's guard
// within crypto's, records whether DIT is set, and DIT is read again after hkdf returns, inside
// crypto's guard alone; after both it is as it was before, from clear and from set. Ed25519ph's
// prehash, hash's sha2_512, is unkeyed: a signature enters crypto's guard alone.

#include "support/timing_seam.hpp"

#include "support/timing_dit.hpp"

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/backends/hash2.hpp>
#include <webcpp/hash/hkdf.hpp>
#include <webcpp/hash/hmac.hpp>
#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace webcpp::test {
namespace {

/** A backend tag whose ChaCha20-Poly1305 calls hash inside crypto's guard. */
struct timing_hash_stand_in {};

/** Whether the stand-in's seal derived its key. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): what the stand-in records
bool derived_inside = false;

/** Whether DIT was set after hkdf returned, still inside crypto's guard. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): what the stand-in records
bool dit_after_hkdf = false;

/** The updates dit_probe ran since the stand-in's seal began. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): what the probe records
std::size_t probe_updates = 0;

/** The updates dit_probe ran with DIT set. */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): what the probe records
std::size_t probe_updates_with_dit = 0;

/**
 * SHA-256 in Boost.Hash2's form whose every update records, before it hashes, whether DIT is set:
 * hkdf's HMAC runs over it, inside hash's guard.
 */
class dit_probe {
public:
    /** The block size, SHA-256's. */
    static constexpr std::size_t block_size = boost::hash2::sha2_256::block_size;
    /** The result, SHA-256's. */
    using result_type = boost::hash2::sha2_256::result_type;

    /** SHA-256 unseeded. */
    dit_probe() = default;

    /**
     * SHA-256 seeded by an integer, as Hash2's.
     *
     * @param seed The seed.
     */
    explicit dit_probe(std::uint64_t seed) : inner_(seed) {}

    /**
     * SHA-256 seeded by bytes, as Hash2's.
     *
     * @param seed The seed. @param size Its size.
     */
    dit_probe(void const* seed, std::size_t size) : inner_(seed, size) {}

    /**
     * Records whether DIT is set, then hashes `size` bytes at `data`.
     *
     * @param data The bytes. @param size Their number.
     */
    void update(void const* data, std::size_t size) {
        ++probe_updates;
        if (webcpp::secure::dit_is_set()) {
            ++probe_updates_with_dit;
        }
        inner_.update(data, size);
    }

    /** @return SHA-256's result. */
    result_type result() { return inner_.result(); }

private:
    boost::hash2::sha2_256 inner_;
};

}  // namespace
}  // namespace webcpp::test

namespace webcpp::crypto::detail {

/** The stand-in's ChaCha20-Poly1305: seal runs hash's hkdf; every call succeeds. */
template <>
struct aead_engine<families::chacha20_poly1305, test::timing_hash_stand_in> {
    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> init(
        aead_state<families::chacha20_poly1305, test::timing_hash_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*key_bytes*/) noexcept {
        return {};
    }

    /** Derives a key with hash's hkdf, records it and DIT after it, then succeeds. */
    [[nodiscard]] static boost::system::result<void> seal(
        aead_state<families::chacha20_poly1305, test::timing_hash_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*nonce_bytes*/,
        std::span<std::uint8_t const> /*associated_data_bytes*/, std::span<std::uint8_t> /*data*/,
        boost::hash2::digest<16>& /*tag*/) noexcept {
        std::array<std::uint8_t, 32> output_key_material{};
        std::array<std::uint8_t, 16> const salt{};
        std::array<std::uint8_t, 22> const secret{};
        std::array<std::uint8_t, 4> const application_info{};
        test::probe_updates = 0;
        test::probe_updates_with_dit = 0;
        test::derived_inside =
            webcpp::hash::hkdf<webcpp::hash::hmac<test::dit_probe>, webcpp::hash::backends::hash2>(
                output_key_material, salt, secret, application_info)
                .has_value();
        test::dit_after_hkdf = webcpp::secure::dit_is_set();
        return {};
    }

    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> open(
        aead_state<families::chacha20_poly1305, test::timing_hash_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*nonce_bytes*/,
        std::span<std::uint8_t const> /*associated_data_bytes*/, std::span<std::uint8_t> /*data*/,
        std::array<std::uint8_t, 16> const& /*tag*/) noexcept {
        return {};
    }

    /** Nothing to move. */
    static void move(
        aead_state<families::chacha20_poly1305, test::timing_hash_stand_in>& /*to*/,
        aead_state<families::chacha20_poly1305, test::timing_hash_stand_in>& /*from*/) noexcept {}

    /** Nothing to wipe. */
    static void reset(
        aead_state<families::chacha20_poly1305, test::timing_hash_stand_in>& /*state*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

namespace {

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
using cipher = crypto::ciphers::basic_chacha20_poly1305<crypto::families::chacha20_poly1305,
                                                        webcpp::test::timing_hash_stand_in>;

using webcpp::test::force_dit;

/** Whether a recorded `function_name()` is the named function, as the seam support reads it. */
bool entry_is(char const* entered, std::string_view function) {
    return entered != nullptr &&
           webcpp::test::names_function(entered, webcpp::test::function_named(function));
}

// The spec's scenario "A nested foreign guard", from clear and from set.
void hash_inside_crypto() {
    for (bool const initially_set : {false, true}) {
        force_dit(initially_set);
        bool const before = webcpp::secure::dit_is_set();
        std::array<std::uint8_t, cipher::key_size> const key{};
        auto made = cipher::from_key(key);
        if (!BOOST_TEST(made.has_value())) {
            continue;
        }
        std::array<std::uint8_t, cipher::nonce_size> const nonce{};
        std::array<std::uint8_t, 8> data{};
        std::size_t const own_before = webcpp::test::timing_entries;
        std::size_t const all_before = webcpp::test::timing_all_entries;
        webcpp::test::timing_first_entry = nullptr;
        webcpp::test::derived_inside = false;
        BOOST_TEST(made->seal(nonce, {}, data).has_value());
        BOOST_TEST(webcpp::test::derived_inside);
        BOOST_TEST_EQ(webcpp::test::timing_entries, own_before + 1);
        BOOST_TEST_EQ(webcpp::test::timing_all_entries, all_before + 2);
        BOOST_TEST(entry_is(webcpp::test::timing_first_entry, "basic_chacha20_poly1305::seal"));
        BOOST_TEST(entry_is(webcpp::test::timing_last_entry, "webcpp::hash::hkdf"));
        BOOST_TEST(webcpp::test::probe_updates > 0);
        BOOST_TEST_EQ(webcpp::test::probe_updates_with_dit,
                      webcpp::secure::cpu_has_dit() ? webcpp::test::probe_updates : 0);
        BOOST_TEST_EQ(webcpp::test::dit_after_hkdf, webcpp::secure::cpu_has_dit());
        BOOST_TEST_EQ(webcpp::secure::dit_is_set(), before);
    }
    force_dit(false);
}

// Ed25519ph signs with hash's SHA-512 as its prehash, which is unkeyed: crypto's guard alone.
void ed25519ph_uses_hash_unkeyed() {
    using prehashed_signer = ed25519::prehashed_signer<webcpp::hash::sha2_512>;
    // RFC 8032 section 7.1, TEST 1: the secret key (the seed). A local, since a global of this
    // name would be hidden by ed25519.hpp's parameter `seed` (MSVC's C4459, an error at /WX).
    constexpr std::string_view seed =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    auto const key =
        ed25519::basic_keypair<crypto::backends::sodium>::from_secret(webcpp::test::from_hex(seed));
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    std::array<std::uint8_t, 3> const piece{1, 2, 3};
    auto signer = prehashed_signer::begin();
    if (!BOOST_TEST(signer.has_value()) || !BOOST_TEST(signer->update(piece).has_value())) {
        return;
    }
    std::size_t const own_before = webcpp::test::timing_entries;
    std::size_t const all_before = webcpp::test::timing_all_entries;
    BOOST_TEST(signer->sign(*key).has_value());
    BOOST_TEST_EQ(webcpp::test::timing_entries, own_before + 1);
    BOOST_TEST_EQ(webcpp::test::timing_all_entries, all_before + 1);
}

}  // namespace

int main() {
    hash_inside_crypto();
    ed25519ph_uses_hash_unkeyed();
    return webcpp::test::exit_status(boost::report_errors());
}
