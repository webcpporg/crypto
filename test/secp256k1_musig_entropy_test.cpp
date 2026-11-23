// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// MuSig2's nonce with the system's source failing (the test seam
// WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY, a whole-program define, hence a program of its own): the
// planted source answers the key pairs' context seeds, which keypair::from_secret draws from the
// same source, then fails; nonce_gen returns entropy_unavailable, without aborting, after drawing
// exactly once and calling nothing after the failure. That the buffer the draw wrote is zero
// on that failure is random_device::fill's contract, tested by random_device_failing; the wipe
// after a successful draw is detail::secp256k1_secret's destructor's.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
int answer_after = 0;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's tally
std::size_t calls = 0;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the source's next answers
std::uint8_t next_byte = 1;

}  // namespace

extern "C" int webcpp_test_entropy(void* output_bytes, std::size_t byte_count) {
    ++calls;
    // As getentropy does: 0 when it fills, -1 with errno set when it fails.
    if (answer_after == 0) {
        errno = EIO;
        return -1;
    }
    --answer_after;
    std::memset(output_bytes, next_byte++, byte_count);
    return 0;
}

int main() {
    namespace crypto = webcpp::crypto;
    namespace secp = webcpp::crypto::curves::secp256k1;
    namespace musig = webcpp::crypto::curves::secp256k1::musig;

    // The two key pairs' context seeds, then the aggregate key, which draws nothing.
    answer_after = 2;
    std::array<std::uint8_t, 32> first_secret{};
    first_secret.fill(0x11);
    std::array<std::uint8_t, 32> second_secret{};
    second_secret.fill(0x22);
    auto const first = secp::keypair::from_secret(first_secret);
    auto const second = secp::keypair::from_secret(second_secret);
    if (!BOOST_TEST(first && second)) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    BOOST_TEST_EQ(calls, 2U);
    auto const first_key = first->public_key();
    auto const second_key = second->public_key();
    std::array<secp::public_key, 2> const keys{*first_key, *second_key};
    std::vector<std::byte> space(musig::workspace_size(keys.size()));
    auto const key = musig::key_aggregate(keys, space);
    if (!BOOST_TEST(key.has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    BOOST_TEST_EQ(calls, 2U);

    // The source fails now: the nonce's session randomness is not drawn, and nothing is made.
    auto const refused = musig::nonce_gen(*first, *key);
    BOOST_TEST(!refused && refused.error() == crypto::error::entropy_unavailable);
    BOOST_TEST_EQ(calls, 3U);

    // With the source answering again, the nonce is drawn once.
    answer_after = 1;
    auto const made = musig::nonce_gen(*second, *key);
    BOOST_TEST(made.has_value());
    BOOST_TEST_EQ(calls, 4U);
    return webcpp::test::exit_status(boost::report_errors());
}
