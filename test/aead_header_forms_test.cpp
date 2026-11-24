// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A cipher's header brings its free forms (design D11): with
// <webcpp/crypto/ciphers/chacha20_poly1305.hpp> alone of crypto's headers,
// crypto::secret_key_encryption::aead::seal and open on XChaCha20-Poly1305, its default backend
// libsodium, give the member's ciphertext and tag and open them back.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <type_traits>

namespace crypto = webcpp::crypto;

int main() {
    using xchacha = crypto::ciphers::xchacha20_poly1305<>;
    std::array<std::uint8_t, xchacha::key_size> key{};
    key.fill(3);
    std::array<std::uint8_t, xchacha::nonce_size> const nonce{4};
    std::array<std::uint8_t, 2> const associated_data{'i', 'd'};
    auto made = xchacha::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    std::array<std::uint8_t, 7> const message{'m', 'e', 's', 's', 'a', 'g', 'e'};
    auto by_member = message;
    auto by_free = message;
    auto const member_tag = made->seal(nonce, associated_data, by_member);
    auto const free_tag =
        crypto::secret_key_encryption::aead::seal(*made, nonce, associated_data, by_free);
    static_assert(std::is_same_v<decltype(free_tag), decltype(member_tag)>);
    if (BOOST_TEST(member_tag.has_value()) && BOOST_TEST(free_tag.has_value())) {
        BOOST_TEST(*free_tag == *member_tag);
        BOOST_TEST(by_free == by_member);
        BOOST_TEST(by_free != message);
        BOOST_TEST(crypto::secret_key_encryption::aead::open(
                       *made, nonce, associated_data, by_free,
                       std::span<std::uint8_t const>(free_tag->data(), free_tag->size()))
                       .has_value());
        BOOST_TEST(by_free == message);
    }
    return webcpp::test::exit_status(boost::report_errors());
}
