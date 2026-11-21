// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The coverage of detail::timing_guard by the families every backend shares: each public function
// of the AES block cipher, gcm and ciphers::aead, called once with valid input and once with
// input refused before the backend is reached, must enter a guard and leave the thread's DIT as
// it found it. Each backend's timing_coverage_<backend>_test.cpp calls these on the algorithms
// it builds; a test includes support/timing_seam.hpp before any crypto header, then this one.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_COVERAGE_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_COVERAGE_HPP

#include "timing_seam.hpp"

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace webcpp::test {

/**
 * Runs `call` and reports an error when it entered no detail::timing_guard, when the first guard
 * it entered is not the one of `function` (support/timing_seam.hpp), or when it left the thread's
 * DIT other than it found it.
 *
 * @param name What the call is, `<family>::<function>[ how] on <backend>`, as an error names it.
 * @param function The function whose guard the call must enter first, `<scope>::<identifier>`,
 * where the name cannot say it (an alias of a class template, an operator, a constructor).
 * @param call The call, with its arguments bound.
 */
template <class Call>
void covered(std::string const& name, std::string const& function, Call&& call) {
    bool const before = webcpp::crypto::detail::dit_is_set();
    require_enters(name, function, std::forward<Call>(call));
    if (webcpp::crypto::detail::dit_is_set() != before) {
        std::string const message = name + " left DIT other than it found it";
        BOOST_ERROR(message.c_str());
    }
}

/**
 * `covered`, for a call whose name begins with the function whose guard it must enter first,
 * `<qualifiers>::<scope>::<identifier>`.
 *
 * @param name What the call is, `<family>::<function>[ how] on <backend>`, as an error names it.
 * @param call The call, with its arguments bound.
 */
template <class Call>
void covered(std::string const& name, Call&& call) {
    covered(name, name, std::forward<Call>(call));
}

/** A key of `Size` bytes whose bytes differ from one another. */
template <std::size_t Size>
std::array<std::uint8_t, Size> coverage_key() {
    std::array<std::uint8_t, Size> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>((i * 29) + 3);
    }
    return key;
}

/**
 * The AES block cipher's guarded functions: `make`, a key of the wrong size included, `encrypt`
 * and `decrypt`, a partial block included.
 *
 * @tparam Cipher `aes128<Backend>`, `aes192<Backend>` or `aes256<Backend>`.
 * @param family The cipher's name, `aes128`, `aes192` or `aes256`.
 * @param backend The backend's name.
 */
template <class Cipher>
void cover_aes(std::string const& family, std::string const& backend) {
    std::string const on = " on " + backend;
    auto const key = coverage_key<Cipher::key_size>();
    covered(family + "::make" + on, [&key] { BOOST_TEST(Cipher::make(key).has_value()); });
    covered(family + "::make with a short key" + on, [&key] {
        BOOST_TEST(Cipher::make(std::span(key).first(Cipher::key_size - 1)).error() ==
                   webcpp::crypto::error::invalid_key_size);
    });
    auto made = Cipher::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 2 * Cipher::block_size> data{};
    covered(family + "::encrypt" + on, "basic_aes::encrypt",
            [&made, &data] { BOOST_TEST(made->encrypt(data).has_value()); });
    covered(family + "::decrypt" + on, "basic_aes::decrypt",
            [&made, &data] { BOOST_TEST(made->decrypt(data).has_value()); });
    covered(family + "::encrypt of a partial block" + on, "basic_aes::encrypt", [&made, &data] {
        BOOST_TEST(made->encrypt(std::span(data).first(1)).error() ==
                   webcpp::crypto::error::invalid_input_size);
    });
    covered(family + "::decrypt of a partial block" + on, "basic_aes::decrypt", [&made, &data] {
        BOOST_TEST(made->decrypt(std::span(data).first(1)).error() ==
                   webcpp::crypto::error::invalid_input_size);
    });
}

/**
 * gcm's guarded functions on a message: `seal` and `open`, an IV of no byte included, and the
 * incremental `begin_seal`, `update` and `result`, each refused once too.
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param made A keyed object, with no message in progress, as it is left.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param on ` on <backend>`, which ends each name.
 */
template <class Gcm>
void cover_gcm_messages(Gcm& made, std::string const& family, std::string const& on) {
    std::array<std::uint8_t, Gcm::iv_size> const iv{};
    std::array<std::uint8_t, 4> const additional_data{1, 2, 3, 4};
    std::array<std::uint8_t, 40> data{};
    typename Gcm::result_type tag{};
    covered(family + "::seal" + on, "gcm::seal", [&] {
        auto const sealed = made.seal(iv, additional_data, data);
        if (BOOST_TEST(sealed.has_value())) {
            tag = *sealed;
        }
    });
    covered(family + "::open" + on, "gcm::open", [&] {
        BOOST_TEST(
            made.open(iv, additional_data, data, std::span(tag.data(), tag.size())).has_value());
    });
    covered(family + "::seal with an empty IV" + on, "gcm::seal", [&] {
        BOOST_TEST(made.seal({}, additional_data, data).error() ==
                   webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::open with an empty IV" + on, "gcm::open", [&] {
        BOOST_TEST(
            made.open({}, additional_data, data, std::span(tag.data(), tag.size())).error() ==
            webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::begin_seal" + on, "gcm::begin_seal",
            [&] { BOOST_TEST(made.begin_seal(iv, additional_data).has_value()); });
    covered(family + "::update" + on, "gcm::update",
            [&] { BOOST_TEST(made.update(data).has_value()); });
    covered(family + "::result" + on, "gcm::result",
            [&] { BOOST_TEST(made.result().has_value()); });
    covered(family + "::begin_seal with an empty IV" + on, "gcm::begin_seal", [&] {
        BOOST_TEST(made.begin_seal({}, additional_data).error() ==
                   webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::update without a message" + on, "gcm::update",
            [&] { BOOST_TEST(made.update(data).error() == webcpp::crypto::error::invalid_state); });
    covered(family + "::result without a message" + on, "gcm::result",
            [&] { BOOST_TEST(made.result().error() == webcpp::crypto::error::invalid_state); });
}

/**
 * gcm's move constructor and move assignment, which run the backend (ruling R3), of a keyed
 * object and of one in the middle of `begin_seal`. Each check does the move alone, so that no
 * other guarded function raises the count.
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param on ` on <backend>`, which ends each name.
 */
template <class Gcm>
void cover_gcm_moves(std::string const& family, std::string const& on) {
    auto const key = coverage_key<Gcm::key_size>();
    std::array<std::uint8_t, Gcm::iv_size> const iv{};
    auto keyed = Gcm::make(key);
    auto other_keyed = Gcm::make(key);
    auto target = Gcm::make(key);
    auto in_message = Gcm::make(key);
    auto in_other_message = Gcm::make(key);
    if (!BOOST_TEST(keyed.has_value()) || !BOOST_TEST(other_keyed.has_value()) ||
        !BOOST_TEST(target.has_value()) || !BOOST_TEST(in_message.has_value()) ||
        !BOOST_TEST(in_other_message.has_value()) ||
        !BOOST_TEST(in_message->begin_seal(iv, {}).has_value()) ||
        !BOOST_TEST(in_other_message->begin_seal(iv, {}).has_value())) {
        return;
    }
    covered(family + "::gcm(gcm&&) of a keyed object" + on, "gcm::gcm",
            [&keyed] { [[maybe_unused]] Gcm const moved(std::move(*keyed)); });
    covered(family + "::operator=(gcm&&) of a keyed object" + on,
            "gcm::operator=", [&other_keyed, &target] { *target = std::move(*other_keyed); });
    covered(family + "::gcm(gcm&&) during begin_seal" + on, "gcm::gcm",
            [&in_message] { [[maybe_unused]] Gcm const moved(std::move(*in_message)); });
    covered(family + "::operator=(gcm&&) during begin_seal" + on, "gcm::operator=",
            [&in_other_message, &target] { *target = std::move(*in_other_message); });
}

/**
 * gcm's guarded functions: `make`, a key of the wrong size included; those on a message
 * (`cover_gcm_messages`); and the moves (`cover_gcm_moves`).
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param backend The backend's name.
 */
template <class Gcm>
void cover_gcm(std::string const& family, std::string const& backend) {
    std::string const on = " on " + backend;
    auto const key = coverage_key<Gcm::key_size>();
    covered(family + "::make" + on, "gcm::make",
            [&key] { BOOST_TEST(Gcm::make(key).has_value()); });
    covered(family + "::make with a short key" + on, "gcm::make", [&key] {
        BOOST_TEST(Gcm::make(std::span(key).first(Gcm::key_size - 1)).error() ==
                   webcpp::crypto::error::invalid_key_size);
    });
    auto made = Gcm::make(key);
    if (BOOST_TEST(made.has_value())) {
        cover_gcm_messages(*made, family, on);
    }
    cover_gcm_moves<Gcm>(family, on);
}

/**
 * ciphers::aead's guarded functions: `make`, a key of the wrong size included, `seal` and
 * `open`, a nonce of the wrong size included.
 *
 * @tparam Aead `aead<Family, Backend>`: ChaCha20-Poly1305 and its forms, or a secret box.
 * @param family The family's name, as the public alias spells it.
 * @param backend The backend's name.
 */
template <class Aead>
void cover_aead(std::string const& family, std::string const& backend) {
    std::string const on = " on " + backend;
    auto const key = coverage_key<Aead::key_size>();
    covered(family + "::make" + on, "aead::make",
            [&key] { BOOST_TEST(Aead::make(key).has_value()); });
    covered(family + "::make with a short key" + on, "aead::make", [&key] {
        BOOST_TEST(Aead::make(std::span(key).first(Aead::key_size - 1)).error() ==
                   webcpp::crypto::error::invalid_key_size);
    });
    auto made = Aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 40> data{};
    typename Aead::result_type tag{};
    covered(family + "::seal" + on, "aead::seal", [&] {
        auto const sealed = made->seal(iv, {}, data);
        if (BOOST_TEST(sealed.has_value())) {
            tag = *sealed;
        }
    });
    covered(family + "::open" + on, "aead::open", [&] {
        BOOST_TEST(made->open(iv, {}, data, std::span(tag.data(), tag.size())).has_value());
    });
    covered(family + "::seal with a short nonce" + on, "aead::seal", [&] {
        BOOST_TEST(made->seal(std::span(iv).first(Aead::iv_size - 1), {}, data).error() ==
                   webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::open with a short nonce" + on, "aead::open", [&] {
        BOOST_TEST(made->open(std::span(iv).first(Aead::iv_size - 1), {}, data,
                              std::span(tag.data(), tag.size()))
                       .error() == webcpp::crypto::error::invalid_iv_size);
    });
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_COVERAGE_HPP
