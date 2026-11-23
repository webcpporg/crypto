// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The coverage of detail::timing_guard by the families every backend shares: each public function
// of the AES block cipher, gcm and ciphers::aead, and the free crypto::make, crypto::seal and
// crypto::open that call gcm's and aead's, called once with valid input and once with input
// refused before the backend is reached, must enter a guard and leave the thread's DIT as
// it found it. Each backend's timing_coverage_<backend>_test.cpp calls these on the algorithms
// it builds; a test includes support/timing_seam.hpp before any crypto header, then this one.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_COVERAGE_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_COVERAGE_HPP

#include "timing_seam.hpp"

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
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
 * The bytes gcm's coverage reads and writes: the IV, the additional data, the data, which a seal
 * turns into the ciphertext that the open reads, and the seal's tag.
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 */
template <class Gcm>
struct gcm_coverage_message {
    /** An IV of the size gcm takes. */
    std::array<std::uint8_t, Gcm::iv_size> iv{};
    /** Four bytes of additional data. */
    std::array<std::uint8_t, 4> additional_data{1, 2, 3, 4};
    /** The data, sealed and opened in place. */
    std::array<std::uint8_t, 40> data{};
    /** The tag of the last seal. */
    Gcm::result_type tag{};
};

/**
 * gcm's one-shot `seal` and `open`, and the free `crypto::seal` and `crypto::open` that call
 * them, an IV of no byte included.
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param made A keyed object, with no message in progress, as it is left.
 * @param message The bytes; `data` and `tag` are left sealed.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param on ` on <backend>`, which ends each name.
 */
template <class Gcm>
void cover_gcm_one_shot(Gcm& made, gcm_coverage_message<Gcm>& message, std::string const& family,
                        std::string const& on) {
    covered(family + " crypto::seal" + on, "crypto::seal", [&] {
        auto const sealed =
            webcpp::crypto::seal(made, message.iv, message.additional_data, message.data);
        if (BOOST_TEST(sealed.has_value())) {
            message.tag = *sealed;
        }
    });
    covered(family + " crypto::open" + on, "crypto::open", [&] {
        BOOST_TEST(webcpp::crypto::open(made, message.iv, message.additional_data, message.data,
                                        std::span(message.tag.data(), message.tag.size()))
                       .has_value());
    });
    covered(family + " crypto::seal with an empty IV" + on, "crypto::seal", [&] {
        BOOST_TEST(webcpp::crypto::seal(made, {}, message.additional_data, message.data).error() ==
                   webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + " crypto::open with an empty IV" + on, "crypto::open", [&] {
        BOOST_TEST(webcpp::crypto::open(made, {}, message.additional_data, message.data,
                                        std::span(message.tag.data(), message.tag.size()))
                       .error() == webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::seal" + on, "gcm::seal", [&] {
        auto const sealed = made.seal(message.iv, message.additional_data, message.data);
        if (BOOST_TEST(sealed.has_value())) {
            message.tag = *sealed;
        }
    });
    covered(family + "::open" + on, "gcm::open", [&] {
        BOOST_TEST(made.open(message.iv, message.additional_data, message.data,
                             std::span(message.tag.data(), message.tag.size()))
                       .has_value());
    });
    covered(family + "::seal with an empty IV" + on, "gcm::seal", [&] {
        BOOST_TEST(made.seal({}, message.additional_data, message.data).error() ==
                   webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::open with an empty IV" + on, "gcm::open", [&] {
        BOOST_TEST(made.open({}, message.additional_data, message.data,
                             std::span(message.tag.data(), message.tag.size()))
                       .error() == webcpp::crypto::error::invalid_iv_size);
    });
}

/**
 * gcm's incremental `begin_seal`, `update` and `result`, each refused once too.
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param made A keyed object, with no message in progress, as it is left.
 * @param message The bytes; `data` is left holding the one-shot seal's ciphertext again.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param on ` on <backend>`, which ends each name.
 */
template <class Gcm>
void cover_gcm_incremental_seal(Gcm& made, gcm_coverage_message<Gcm>& message,
                                std::string const& family, std::string const& on) {
    covered(family + "::begin_seal" + on, "gcm::begin_seal",
            [&] { BOOST_TEST(made.begin_seal(message.iv, message.additional_data).has_value()); });
    covered(family + "::update" + on, "gcm::update",
            [&] { BOOST_TEST(made.update(message.data).has_value()); });
    covered(family + "::result" + on, "gcm::result",
            [&] { BOOST_TEST(made.result().has_value()); });
    covered(family + "::begin_seal with an empty IV" + on, "gcm::begin_seal", [&] {
        BOOST_TEST(made.begin_seal({}, message.additional_data).error() ==
                   webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::update without a message" + on, "gcm::update", [&] {
        BOOST_TEST(made.update(message.data).error() == webcpp::crypto::error::invalid_state);
    });
    covered(family + "::result without a message" + on, "gcm::result",
            [&] { BOOST_TEST(made.result().error() == webcpp::crypto::error::invalid_state); });
}

/**
 * gcm's incremental `begin_open`, `authenticate`, `verify`, `decrypt` and `end_open`, each
 * refused once too.
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param made A keyed object, with no message in progress, as it is left.
 * @param message The bytes: `data` the ciphertext of `tag`'s seal, which the open reads.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param on ` on <backend>`, which ends each name.
 */
template <class Gcm>
void cover_gcm_incremental_open(Gcm& made, gcm_coverage_message<Gcm>& message,
                                std::string const& family, std::string const& on) {
    covered(family + "::begin_open" + on, "gcm::begin_open",
            [&] { BOOST_TEST(made.begin_open(message.iv, message.additional_data).has_value()); });
    covered(family + "::authenticate" + on, "gcm::authenticate",
            [&] { BOOST_TEST(made.authenticate(message.data).has_value()); });
    covered(family + "::verify" + on, "gcm::verify", [&] {
        BOOST_TEST(made.verify(std::span(message.tag.data(), message.tag.size())).has_value());
    });
    covered(family + "::decrypt" + on, "gcm::decrypt",
            [&] { BOOST_TEST(made.decrypt(message.data).has_value()); });
    covered(family + "::end_open" + on, "gcm::end_open",
            [&] { BOOST_TEST(made.end_open().has_value()); });
    covered(family + "::begin_open with an empty IV" + on, "gcm::begin_open", [&] {
        BOOST_TEST(made.begin_open({}, message.additional_data).error() ==
                   webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + "::authenticate without a message" + on, "gcm::authenticate", [&] {
        BOOST_TEST(made.authenticate(message.data).error() == webcpp::crypto::error::invalid_state);
    });
    covered(family + "::verify without a message" + on, "gcm::verify", [&] {
        BOOST_TEST(made.verify(std::span(message.tag.data(), message.tag.size())).error() ==
                   webcpp::crypto::error::invalid_state);
    });
    covered(family + "::decrypt without a message" + on, "gcm::decrypt", [&] {
        BOOST_TEST(made.decrypt(message.data).error() == webcpp::crypto::error::invalid_state);
    });
    covered(family + "::end_open without a message" + on, "gcm::end_open",
            [&] { BOOST_TEST(made.end_open().error() == webcpp::crypto::error::invalid_state); });
}

/**
 * gcm's guarded functions on a message: `seal` and `open`, an IV of no byte included, the
 * incremental `begin_seal`, `update` and `result`, and the incremental `begin_open`,
 * `authenticate`, `verify`, `decrypt` and `end_open`, each refused once too.
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param made A keyed object, with no message in progress, as it is left.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param on ` on <backend>`, which ends each name.
 */
template <class Gcm>
void cover_gcm_messages(Gcm& made, std::string const& family, std::string const& on) {
    gcm_coverage_message<Gcm> message;
    cover_gcm_one_shot(made, message, family, on);
    cover_gcm_incremental_seal(made, message, family, on);
    // data holds the ciphertext of the seal above again, which the incremental open reads.
    cover_gcm_incremental_open(made, message, family, on);
}

/**
 * gcm's move constructor and move assignment, which run the backend (ruling R3), of a keyed
 * object and of one in the middle of `begin_seal`, and the move constructor of one in the
 * middle of `begin_open`. Each check does the move alone, so that no other guarded function
 * raises the count.
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
    auto in_open = Gcm::make(key);
    if (!BOOST_TEST(keyed.has_value()) || !BOOST_TEST(other_keyed.has_value()) ||
        !BOOST_TEST(target.has_value()) || !BOOST_TEST(in_message.has_value()) ||
        !BOOST_TEST(in_other_message.has_value()) || !BOOST_TEST(in_open.has_value()) ||
        !BOOST_TEST(in_message->begin_seal(iv, {}).has_value()) ||
        !BOOST_TEST(in_other_message->begin_seal(iv, {}).has_value()) ||
        !BOOST_TEST(in_open->begin_open(iv, {}).has_value())) {
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
    covered(family + "::gcm(gcm&&) during begin_open" + on, "gcm::gcm",
            [&in_open] { [[maybe_unused]] Gcm const moved(std::move(*in_open)); });
}

/**
 * gcm's guarded functions: `make` and the free `crypto::make`, a key of the wrong size included;
 * those on a message (`cover_gcm_messages`); and the moves (`cover_gcm_moves`).
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
    covered(family + " crypto::make" + on, "crypto::make",
            [&key] { BOOST_TEST(webcpp::crypto::make<Gcm>(key).has_value()); });
    covered(family + " crypto::make with a short key" + on, "crypto::make", [&key] {
        BOOST_TEST(webcpp::crypto::make<Gcm>(std::span(key).first(Gcm::key_size - 1)).error() ==
                   webcpp::crypto::error::invalid_key_size);
    });
    auto made = Gcm::make(key);
    if (BOOST_TEST(made.has_value())) {
        cover_gcm_messages(*made, family, on);
    }
    cover_gcm_moves<Gcm>(family, on);
}

/**
 * A completion handler of the `cover_async_*` functions that counts its completions and, given a
 * tag's address, keeps the tag. Not a lambda: a lambda in a template argument keeps
 * `names_function` from reading the guard's function (support/timing_seam.hpp).
 */
template <class Tag = void>
struct async_completion_counter {
    /** Counts the completion. */
    int* completions = nullptr;
    /** Where a seal's tag is kept, or null. */
    Tag* tag = nullptr;

    /** A completion with an error code alone. */
    void operator()(boost::system::error_code /*code*/) const { ++*completions; }

    /** A completion with a value, which is the tag of a seal or an object that is dropped. */
    template <class Value>
    void operator()(boost::system::error_code /*code*/, Value&& value) const {
        ++*completions;
        if constexpr (std::is_same_v<std::remove_cvref_t<Value>, Tag>) {
            if (tag != nullptr) {
                *tag = value;
            }
        }
    }
};

/**
 * gcm's asynchronous functions, `async_make`, `async_seal` and `async_open`, free and member, each
 * called with valid input and with input refused before the backend, an `io_context` run after
 * each call so that its completion is delivered. The first guard each enters is its own (the
 * member a free one calls, and the synchronous call the member makes, hold others, which run
 * after).
 *
 * @tparam Gcm `gcm<aes128<Backend>>`, `gcm<aes192<Backend>>` or `gcm<aes256<Backend>>`.
 * @param family The algorithm's name, `aes128_gcm` or `aes256_gcm`.
 * @param backend The backend's name.
 */
template <class Gcm>
void cover_async_gcm(std::string const& family, std::string const& backend) {
    namespace crypto = webcpp::crypto;
    std::string const on = " on " + backend;
    webcpp::asio::io_context context;
    auto const executor = context.get_executor();
    auto const key = coverage_key<Gcm::key_size>();
    int completions = 0;
    typename Gcm::result_type kept{};
    async_completion_counter<typename Gcm::result_type> const counted{.completions = &completions};
    async_completion_counter<typename Gcm::result_type> const keeping{
        .completions = &completions,
        .tag = &kept,
    };
    // Each call's completion is delivered before the next call.
    auto const deliver = [&context] {
        context.restart();
        context.run();  // lint-run: the test's event loop
    };
    covered(family + "::async_make" + on, "crypto::async_make", [&] {
        crypto::async_make<Gcm>(executor, key, counted);
        deliver();
    });
    covered(family + "::async_make with a short key" + on, "crypto::async_make", [&] {
        crypto::async_make<Gcm>(executor, std::span(key).first(Gcm::key_size - 1), counted);
        deliver();
    });
    covered(family + "::async_make, the member," + on, "gcm::async_make", [&] {
        Gcm::async_make(executor, key, counted);
        deliver();
    });
    covered(family + "::async_make, the member, with a short key" + on, "gcm::async_make", [&] {
        Gcm::async_make(executor, std::span(key).first(Gcm::key_size - 1), counted);
        deliver();
    });
    auto made = Gcm::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    gcm_coverage_message<Gcm> message;
    covered(family + "::async_seal" + on, "crypto::async_seal", [&] {
        crypto::async_seal(executor, *made, message.iv, message.additional_data, message.data,
                           keeping);
        deliver();
    });
    covered(family + "::async_open" + on, "crypto::async_open", [&] {
        crypto::async_open(executor, *made, message.iv, message.additional_data, message.data,
                           std::span(kept.data(), kept.size()), counted);
        deliver();
    });
    covered(family + "::async_seal with an empty IV" + on, "crypto::async_seal", [&] {
        crypto::async_seal(executor, *made, {}, message.additional_data, message.data, counted);
        deliver();
    });
    covered(family + "::async_open with an empty IV" + on, "crypto::async_open", [&] {
        crypto::async_open(executor, *made, {}, message.additional_data, message.data,
                           std::span(kept.data(), kept.size()), counted);
        deliver();
    });
    covered(family + "::async_seal, the member," + on, "gcm::async_seal", [&] {
        made->async_seal(executor, message.iv, message.additional_data, message.data, keeping);
        deliver();
    });
    covered(family + "::async_open, the member," + on, "gcm::async_open", [&] {
        made->async_open(executor, message.iv, message.additional_data, message.data,
                         std::span(kept.data(), kept.size()), counted);
        deliver();
    });
    covered(family + "::async_seal, the member, with an empty IV" + on, "gcm::async_seal", [&] {
        made->async_seal(executor, {}, message.additional_data, message.data, counted);
        deliver();
    });
    covered(family + "::async_open, the member, with an empty IV" + on, "gcm::async_open", [&] {
        made->async_open(executor, {}, message.additional_data, message.data,
                         std::span(kept.data(), kept.size()), counted);
        deliver();
    });
    BOOST_TEST_EQ(completions, 12);
}

/**
 * Ed25519's asynchronous functions, `async_make`, `async_generate`, `async_sign` and
 * `async_verify` (both overloads, without and with the policy), free and member, each called with
 * valid input and with input refused before the backend (a seed of 31 bytes, a signature of 63, a
 * moved-from key pair), an `io_context` run after each call so that its completion is delivered.
 * The first guard each enters is its own (the member a free one calls, and the synchronous call
 * the member makes, hold others, which run after).
 *
 * @tparam Keypair `curves::ed25519::basic_keypair<Backend>`.
 * @param backend The backend's name.
 */
template <class Keypair>
void cover_async_ed25519(std::string const& backend) {
    namespace crypto = webcpp::crypto;
    using signature_type = std::array<std::uint8_t, 64>;
    using backend_type = Keypair::backend_type;
    std::string const on = " on " + backend;
    webcpp::asio::io_context context;
    auto const executor = context.get_executor();
    auto const seed = coverage_key<Keypair::seed_size>();
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    int completions = 0;
    signature_type kept{};
    async_completion_counter<signature_type> const counted{.completions = &completions};
    async_completion_counter<signature_type> const keeping{
        .completions = &completions,
        .tag = &kept,
    };
    // Each call's completion is delivered before the next call.
    auto const deliver = [&context] {
        context.restart();
        context.run();  // lint-run: the test's event loop
    };
    covered("ed25519::async_make" + on, "crypto::async_make", [&] {
        crypto::async_make<Keypair>(executor, seed, counted);
        deliver();
    });
    covered("ed25519::async_make with a short seed" + on, "crypto::async_make", [&] {
        crypto::async_make<Keypair>(executor, std::span(seed).first(Keypair::seed_size - 1),
                                    counted);
        deliver();
    });
    covered("ed25519::async_generate" + on, "crypto::async_generate", [&] {
        crypto::async_generate<Keypair>(executor, counted);
        deliver();
    });
    covered("ed25519::basic_keypair::async_make" + on, [&] {
        Keypair::async_make(executor, seed, counted);
        deliver();
    });
    covered("ed25519::basic_keypair::async_make with a short seed" + on, [&] {
        Keypair::async_make(executor, std::span(seed).first(Keypair::seed_size - 1), counted);
        deliver();
    });
    covered("ed25519::basic_keypair::async_generate" + on, [&] {
        Keypair::async_generate(executor, counted);
        deliver();
    });
    auto made = Keypair::make(seed);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        return;
    }
    covered("ed25519::async_sign" + on, "crypto::async_sign", [&] {
        crypto::async_sign(executor, *made, crypto::eddsa, message, keeping);
        deliver();
    });
    covered("ed25519::async_verify" + on, "crypto::async_verify", [&] {
        crypto::async_verify<backend_type>(executor, crypto::eddsa, kept, message, *public_key,
                                           counted);
        deliver();
    });
    covered("ed25519::async_verify with its policy" + on, "crypto::async_verify", [&] {
        crypto::async_verify<backend_type>(executor, crypto::eddsa, kept, message, *public_key,
                                           crypto::curves::ed25519::strict, counted);
        deliver();
    });
    covered("ed25519::async_verify with a short signature" + on, "crypto::async_verify", [&] {
        crypto::async_verify<backend_type>(executor, crypto::eddsa, std::span(kept).first(63),
                                           message, *public_key, counted);
        deliver();
    });
    covered("ed25519::basic_keypair::async_sign" + on, [&] {
        made->async_sign(executor, crypto::eddsa, message, counted);
        deliver();
    });
    covered("ed25519::public_key::async_verify" + on, [&] {
        public_key->template async_verify<backend_type>(executor, crypto::eddsa, kept, message,
                                                        counted);
        deliver();
    });
    covered("ed25519::public_key::async_verify with its policy" + on, [&] {
        public_key->template async_verify<backend_type>(executor, crypto::eddsa, kept, message,
                                                        crypto::curves::ed25519::strict, counted);
        deliver();
    });
    covered("ed25519::public_key::async_verify with a short signature" + on, [&] {
        public_key->template async_verify<backend_type>(
            executor, crypto::eddsa, std::span(kept).first(63), message, counted);
        deliver();
    });
    [[maybe_unused]] Keypair const taken(std::move(*made));
    covered("ed25519::async_sign moved from" + on, "crypto::async_sign", [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        crypto::async_sign(executor, *made, crypto::eddsa, message, counted);
        deliver();
    });
    covered("ed25519::basic_keypair::async_sign moved from" + on, [&] {
        // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
        made->async_sign(executor, crypto::eddsa, message, counted);
        deliver();
    });
    BOOST_TEST_EQ(completions, 16);
}

/**
 * X25519's asynchronous `async_agree`, called with valid input and with a key of 31 bytes, an
 * `io_context` run after each call so that its completion is delivered. Its first guard is its
 * own (the synchronous call it makes holds others, which run after).
 *
 * @tparam Backend The backend of X25519.
 * @param backend The backend's name.
 */
template <class Backend>
void cover_async_x25519(std::string const& backend) {
    namespace crypto = webcpp::crypto;
    std::string const on = " on " + backend;
    webcpp::asio::io_context context;
    auto const executor = context.get_executor();
    auto const alice = coverage_key<32>();
    auto bob_secret = coverage_key<32>();
    bob_secret[0] ^= 0x42U;
    auto const bob = crypto::curves::x25519::public_key<Backend>(bob_secret);
    if (!BOOST_TEST(bob.has_value())) {
        return;
    }
    int completions = 0;
    async_completion_counter<> const counted{.completions = &completions};
    covered("x25519::async_agree" + on, "crypto::async_agree", [&] {
        crypto::async_agree<Backend>(executor, alice, *bob, counted);
        context.restart();
        context.run();  // lint-run: the test's event loop
    });
    covered("x25519::async_agree with a short key" + on, "crypto::async_agree", [&] {
        crypto::async_agree<Backend>(executor, std::span(alice).first(31), *bob, counted);
        context.restart();
        context.run();  // lint-run: the test's event loop
    });
    BOOST_TEST_EQ(completions, 2);
}

/**
 * The free `crypto::make`, `crypto::seal` and `crypto::open` over a `ciphers::aead`, each
 * entering its own guard before the member's, a key and a nonce of the wrong size included.
 *
 * @tparam Aead `aead<Family, Backend>`: ChaCha20-Poly1305 and its forms, or a secret box.
 * @param family The family's name, as the public alias spells it.
 * @param on ` on <backend>`, which ends each name.
 */
template <class Aead>
void cover_aead_free_forms(std::string const& family, std::string const& on) {
    auto const key = coverage_key<Aead::key_size>();
    covered(family + " crypto::make" + on, "crypto::make",
            [&key] { BOOST_TEST(webcpp::crypto::make<Aead>(key).has_value()); });
    covered(family + " crypto::make with a short key" + on, "crypto::make", [&key] {
        BOOST_TEST(webcpp::crypto::make<Aead>(std::span(key).first(Aead::key_size - 1)).error() ==
                   webcpp::crypto::error::invalid_key_size);
    });
    auto made = Aead::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 40> data{};
    typename Aead::result_type tag{};
    covered(family + " crypto::seal" + on, "crypto::seal", [&] {
        auto const sealed = webcpp::crypto::seal(*made, iv, {}, data);
        if (BOOST_TEST(sealed.has_value())) {
            tag = *sealed;
        }
    });
    covered(family + " crypto::open" + on, "crypto::open", [&] {
        BOOST_TEST(webcpp::crypto::open(*made, iv, {}, data, std::span(tag.data(), tag.size()))
                       .has_value());
    });
    covered(family + " crypto::seal with a short nonce" + on, "crypto::seal", [&] {
        BOOST_TEST(
            webcpp::crypto::seal(*made, std::span(iv).first(Aead::iv_size - 1), {}, data).error() ==
            webcpp::crypto::error::invalid_iv_size);
    });
    covered(family + " crypto::open with a short nonce" + on, "crypto::open", [&] {
        BOOST_TEST(webcpp::crypto::open(*made, std::span(iv).first(Aead::iv_size - 1), {}, data,
                                        std::span(tag.data(), tag.size()))
                       .error() == webcpp::crypto::error::invalid_iv_size);
    });
}

/**
 * ciphers::aead's guarded functions: `make`, a key of the wrong size included, `seal` and
 * `open`, a nonce of the wrong size included, and the free forms that call them
 * (`cover_aead_free_forms`).
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
    cover_aead_free_forms<Aead>(family, on);
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_TIMING_COVERAGE_HPP
