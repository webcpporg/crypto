// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The asynchronous seal, open and from_key of the AEADs and boxes WebCrypto lacks, on libsodium,
// a synchronous backend (design D6): each runs the synchronous member when the operation is
// initiated and completes through a post, never inside the call.
// - xchacha_async (the specification's case): in a coroutine,
//   secret_key_encryption::aead::async_seal of ciphers::xchacha20_poly1305 completes with the
//   synchronous seal's tag and ciphertext, free and member, then async_open restores the
//   plaintext, free and member; the same for ChaCha20-Poly1305 and its original form.
// - box_async: the same for both secret boxes and both crypto_boxes through the box forms,
//   secret_key_encryption::async_seal and async_open, free and member.
// - from_key_async: crypto::async_from_key and the static C::async_from_key of every AEAD and
//   secret box give an object that seals as from_key's does; a short key completes with
//   invalid_key_size and an empty object, which refuses with invalid_state.
// - never_inline (review focus 4): a callback's flag is unset when async_seal and async_open
//   return and set after the context runs, free and member, for an AEAD, a secret box and a
//   crypto_box.
// - wrong_tag: a wrong tag completes with authentication_failed and zeroed data, for an AEAD and
//   a box, free and member.
// - At compile time, on a stand-in backend that completes by itself: the asynchronous forms refuse
//   every AEAD and box but AES-GCM, a const AES-GCM included among those they accept.

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/asynchronous.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/secret_key_encryption/aead.hpp>
#include <webcpp/crypto/secret_key_encryption/authenticated_box.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>
#include <webcpp/test/exit_status.hpp>

#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/this_coro.hpp>
#include <webcpp/asio/use_awaitable.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

// A backend that completes by itself, as part B's browser backend will: its types are named, never
// made.
struct stand_in_browser {};

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

// Which types the asynchronous forms refuse on such a backend (design D6): every AEAD and box but
// AES-GCM, whatever its qualifiers, and none on a synchronous backend. A const AES-GCM is AES-GCM,
// which reaches its own path.
static_assert(webcpp::crypto::detail::refuses_async_aead_v<
              webcpp::crypto::ciphers::xchacha20_poly1305<stand_in_browser>>);
static_assert(webcpp::crypto::detail::refuses_async_aead_v<
              webcpp::crypto::ciphers::xchacha20_poly1305<stand_in_browser> const>);
static_assert(webcpp::crypto::detail::refuses_async_aead_v<
              webcpp::crypto::secret_key_encryption::secretbox<stand_in_browser>&>);
static_assert(!webcpp::crypto::detail::refuses_async_aead_v<
              webcpp::crypto::ciphers::gcm<webcpp::crypto::ciphers::aes256<stand_in_browser>>>);
static_assert(
    !webcpp::crypto::detail::refuses_async_aead_v<
        webcpp::crypto::ciphers::gcm<webcpp::crypto::ciphers::aes256<stand_in_browser>> const>);
static_assert(
    !webcpp::crypto::detail::refuses_async_aead_v<
        webcpp::crypto::ciphers::gcm<webcpp::crypto::ciphers::aes256<stand_in_browser>> const&>);
static_assert(!webcpp::crypto::detail::refuses_async_aead_v<
              webcpp::crypto::ciphers::xchacha20_poly1305<webcpp::crypto::backends::sodium> const>);

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;
namespace aead = crypto::secret_key_encryption::aead;
namespace secret_key_encryption = crypto::secret_key_encryption;

namespace {

using crypto::backends::sodium;
using xchacha = crypto::ciphers::xchacha20_poly1305<sodium>;
using chacha = crypto::ciphers::chacha20_poly1305<sodium>;
using chacha_original = crypto::ciphers::chacha20_poly1305_original<sodium>;
using secretbox = secret_key_encryption::secretbox<sodium>;
using secretbox_xchacha = secret_key_encryption::secretbox_xchacha20poly1305<sodium>;
using box =
    crypto::public_key_encryption::basic_box<crypto::families::box_xsalsa20poly1305, sodium>;
using box_xchacha =
    crypto::public_key_encryption::basic_box<crypto::families::box_xchacha20poly1305, sodium>;

/** The message every case seals: 40 bytes of a pattern. */
constexpr std::array<std::uint8_t, 40> plaintext = [] {
    std::array<std::uint8_t, 40> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>((index * 7U) + 1U);
    }
    return bytes;
}();

/** The associated data of an AEAD's message. */
constexpr std::array<std::uint8_t, 5> associated_data{1, 2, 3, 4, 5};

/** A key of `Size` bytes of 0x42. */
template <std::size_t Size>
std::array<std::uint8_t, Size> test_key() {
    std::array<std::uint8_t, Size> key{};
    key.fill(0x42);
    return key;
}

/** A nonce of `Size` bytes of 0x24. */
template <std::size_t Size>
std::array<std::uint8_t, Size> test_nonce() {
    std::array<std::uint8_t, Size> nonce{};
    nonce.fill(0x24);
    return nonce;
}

bool all_zero(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

/** A keyed AEAD or secret box, from `from_key`. */
template <class Keyed>
Keyed keyed() {
    return Keyed::from_key(test_key<Keyed::key_size>()).value();
}

/** A keyed crypto_box: Alice's, to Bob. */
template <class Box>
Box keyed_box() {
    using keypair = crypto::curves::x25519::basic_keypair<sodium>;
    auto const alice = keypair::from_secret(test_key<32>()).value();
    std::array<std::uint8_t, 32> bob_secret{};
    bob_secret.fill(0x17);
    auto const bob = keypair::from_secret(bob_secret).value();
    return Box::from_keys(alice, bob.public_key().value()).value();
}

/** A keyed object of any of the types: a crypto_box through `from_keys`, the others `from_key`. */
template <class Keyed>
Keyed made() {
    if constexpr (std::is_same_v<Keyed, box> || std::is_same_v<Keyed, box_xchacha>) {
        return keyed_box<Keyed>();
    } else {
        return keyed<Keyed>();
    }
}

/** The synchronous seal's ciphertext and tag, the reference of each asynchronous seal. */
template <class Keyed>
struct sealed_reference {
    std::array<std::uint8_t, 40> ciphertext = plaintext;
    Keyed::result_type tag{};
};

template <class Keyed>
sealed_reference<Keyed> synchronous_seal(Keyed& keyed_object) {
    sealed_reference<Keyed> reference;
    auto const nonce = test_nonce<Keyed::nonce_size>();
    if constexpr (aead::cipher<Keyed>) {
        reference.tag = keyed_object.seal(nonce, associated_data, reference.ciphertext).value();
    } else {
        reference.tag = keyed_object.seal(nonce, reference.ciphertext).value();
    }
    return reference;
}

// An AEAD's seal and open in a coroutine, free and member, each completion the synchronous
// answer.
template <class Cipher>
asio::awaitable<void> aead_round_trip() {
    auto const executor = co_await asio::this_coro::executor;
    auto cipher = keyed<Cipher>();
    auto const reference = synchronous_seal(cipher);
    auto const nonce = test_nonce<Cipher::nonce_size>();

    std::array<std::uint8_t, 40> data = plaintext;
    auto const tag = co_await aead::async_seal(executor, cipher, nonce, associated_data, data,
                                               asio::use_awaitable);
    BOOST_TEST(tag == reference.tag);
    BOOST_TEST(data == reference.ciphertext);
    co_await aead::async_open(executor, cipher, nonce, associated_data, data,
                              std::span(tag.data(), tag.size()), asio::use_awaitable);
    BOOST_TEST(data == plaintext);

    auto const member_tag =
        co_await cipher.async_seal(executor, nonce, associated_data, data, asio::use_awaitable);
    BOOST_TEST(member_tag == reference.tag);
    BOOST_TEST(data == reference.ciphertext);
    co_await cipher.async_open(executor, nonce, associated_data, data,
                               std::span(member_tag.data(), member_tag.size()),
                               asio::use_awaitable);
    BOOST_TEST(data == plaintext);
}

// A box's seal and open in a coroutine through the box forms, free and member.
template <class Box>
asio::awaitable<void> box_round_trip() {
    auto const executor = co_await asio::this_coro::executor;
    Box keyed_object = made<Box>();
    auto const reference = synchronous_seal(keyed_object);
    auto const nonce = test_nonce<Box::nonce_size>();

    std::array<std::uint8_t, 40> data = plaintext;
    auto const tag = co_await secret_key_encryption::async_seal(executor, keyed_object, nonce, data,
                                                                asio::use_awaitable);
    BOOST_TEST(tag == reference.tag);
    BOOST_TEST(data == reference.ciphertext);
    co_await secret_key_encryption::async_open(executor, keyed_object, nonce, data,
                                               std::span(tag.data(), tag.size()),
                                               asio::use_awaitable);
    BOOST_TEST(data == plaintext);

    auto const member_tag =
        co_await keyed_object.async_seal(executor, nonce, data, asio::use_awaitable);
    BOOST_TEST(member_tag == reference.tag);
    BOOST_TEST(data == reference.ciphertext);
    co_await keyed_object.async_open(executor, nonce, data,
                                     std::span(member_tag.data(), member_tag.size()),
                                     asio::use_awaitable);
    BOOST_TEST(data == plaintext);
}

// Runs a coroutine to its end on the context, which it must reach without an exception.
void run_coroutine(asio::io_context& context, asio::awaitable<void> coroutine) {
    bool finished = false;
    asio::co_spawn(context, std::move(coroutine), [&finished](std::exception_ptr const& failure) {
        BOOST_TEST(!failure);
        finished = true;
    });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(finished);
}

void xchacha_async(asio::io_context& context) {
    run_coroutine(context, aead_round_trip<xchacha>());
    run_coroutine(context, aead_round_trip<chacha>());
    run_coroutine(context, aead_round_trip<chacha_original>());
}

void box_async(asio::io_context& context) {
    run_coroutine(context, box_round_trip<secretbox>());
    run_coroutine(context, box_round_trip<secretbox_xchacha>());
    run_coroutine(context, box_round_trip<box>());
    run_coroutine(context, box_round_trip<box_xchacha>());
}

// What one completion of async_from_key handed over.
template <class Keyed>
struct made_completion {
    int calls = 0;
    boost::system::error_code code;
    std::optional<Keyed> value;
};

// The empty object a move leaves, which an error completion gives: every member refuses, and the
// data is untouched.
template <class Keyed>
void check_empty(Keyed& empty_object) {
    std::array<std::uint8_t, 40> data = plaintext;
    auto const nonce = test_nonce<Keyed::nonce_size>();
    if constexpr (aead::cipher<Keyed>) {
        BOOST_TEST(empty_object.seal(nonce, associated_data, data).error() ==
                   crypto::error::invalid_state);
    } else {
        BOOST_TEST(empty_object.seal(nonce, data).error() == crypto::error::invalid_state);
    }
    BOOST_TEST(data == plaintext);
}

// async_from_key, free and static member, against from_key: the object made seals as from_key's.
template <class Keyed>
void from_key_case(asio::io_context& context) {
    auto const key = test_key<Keyed::key_size>();
    auto reference_object = keyed<Keyed>();
    auto const reference = synchronous_seal(reference_object);
    made_completion<Keyed> free_made;
    made_completion<Keyed> member_made;
    made_completion<Keyed> short_made;
    auto const keep = [](made_completion<Keyed>& done) {
        return [&done](boost::system::error_code code, Keyed value) {
            ++done.calls;
            done.code = code;
            done.value.emplace(std::move(value));
        };
    };
    crypto::async_from_key<Keyed>(context.get_executor(), key, keep(free_made));
    Keyed::async_from_key(context.get_executor(), key, keep(member_made));
    crypto::async_from_key<Keyed>(context.get_executor(), std::span(key).first(Keyed::key_size - 1),
                                  keep(short_made));
    BOOST_TEST_EQ(free_made.calls + member_made.calls + short_made.calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    for (made_completion<Keyed>* done : {&free_made, &member_made}) {
        BOOST_TEST_EQ(done->calls, 1);
        BOOST_TEST(!done->code);
        if (BOOST_TEST(done->value.has_value())) {
            auto const sealed = synchronous_seal(*done->value);
            BOOST_TEST(sealed.tag == reference.tag);
            BOOST_TEST(sealed.ciphertext == reference.ciphertext);
        }
    }
    BOOST_TEST_EQ(short_made.calls, 1);
    BOOST_TEST(short_made.code == crypto::error::invalid_key_size);
    if (BOOST_TEST(short_made.value.has_value())) {
        check_empty(*short_made.value);
    }
}

void from_key_async(asio::io_context& context) {
    from_key_case<xchacha>(context);
    from_key_case<chacha>(context);
    from_key_case<chacha_original>(context);
    from_key_case<secretbox>(context);
    from_key_case<secretbox_xchacha>(context);
}

// A flag a callback sets: unset when the initiating call returns, set once the context runs.
template <class Start>
void check_never_inline(asio::io_context& context, Start start) {
    bool called = false;
    start([&called](auto&&...) { called = true; });
    BOOST_TEST(!called);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(called);
}

template <class Keyed>
void never_inline_case(asio::io_context& context) {
    auto keyed_object = made<Keyed>();
    auto const executor = context.get_executor();
    auto const nonce = test_nonce<Keyed::nonce_size>();
    std::array<std::uint8_t, 40> data = plaintext;
    auto const reference = synchronous_seal(keyed_object);
    std::span<std::uint8_t const> const tag(reference.tag.data(), reference.tag.size());
    if constexpr (aead::cipher<Keyed>) {
        check_never_inline(context, [&](auto handler) {
            aead::async_seal(executor, keyed_object, nonce, associated_data, data, handler);
        });
        check_never_inline(context, [&](auto handler) {
            aead::async_open(executor, keyed_object, nonce, associated_data, data, tag, handler);
        });
        check_never_inline(context, [&](auto handler) {
            keyed_object.async_seal(executor, nonce, associated_data, data, handler);
        });
        check_never_inline(context, [&](auto handler) {
            keyed_object.async_open(executor, nonce, associated_data, data, tag, handler);
        });
    } else {
        check_never_inline(context, [&](auto handler) {
            secret_key_encryption::async_seal(executor, keyed_object, nonce, data, handler);
        });
        check_never_inline(context, [&](auto handler) {
            secret_key_encryption::async_open(executor, keyed_object, nonce, data, tag, handler);
        });
        check_never_inline(context, [&](auto handler) {
            keyed_object.async_seal(executor, nonce, data, handler);
        });
        check_never_inline(context, [&](auto handler) {
            keyed_object.async_open(executor, nonce, data, tag, handler);
        });
    }
    BOOST_TEST(data == plaintext);
}

void never_inline(asio::io_context& context) {
    never_inline_case<xchacha>(context);
    never_inline_case<secretbox>(context);
    never_inline_case<box>(context);
}

// A changed tag: authentication_failed, the data zeroed, free and member.
template <class Keyed>
void wrong_tag_case(asio::io_context& context) {
    auto keyed_object = made<Keyed>();
    auto const executor = context.get_executor();
    auto const nonce = test_nonce<Keyed::nonce_size>();
    auto reference = synchronous_seal(keyed_object);
    reference.tag[0] ^= 1U;
    std::span<std::uint8_t const> const tag(reference.tag.data(), reference.tag.size());
    for (bool const member : {false, true}) {
        std::array<std::uint8_t, 40> data = reference.ciphertext;
        boost::system::error_code code;
        auto const keep = [&code](boost::system::error_code done) { code = done; };
        if constexpr (aead::cipher<Keyed>) {
            if (member) {
                keyed_object.async_open(executor, nonce, associated_data, data, tag, keep);
            } else {
                aead::async_open(executor, keyed_object, nonce, associated_data, data, tag, keep);
            }
        } else if (member) {
            keyed_object.async_open(executor, nonce, data, tag, keep);
        } else {
            secret_key_encryption::async_open(executor, keyed_object, nonce, data, tag, keep);
        }
        context.restart();
        context.run();  // lint-run: the test's event loop
        BOOST_TEST(code == crypto::error::authentication_failed);
        BOOST_TEST(all_zero(data));
    }
}

void wrong_tag(asio::io_context& context) {
    wrong_tag_case<xchacha>(context);
    wrong_tag_case<chacha>(context);
    wrong_tag_case<secretbox>(context);
    wrong_tag_case<box_xchacha>(context);
}

}  // namespace

int main() {
    asio::io_context context;
    xchacha_async(context);
    box_async(context);
    from_key_async(context);
    never_inline(context);
    wrong_tag(context);
    return webcpp::test::exit_status(boost::report_errors());
}
