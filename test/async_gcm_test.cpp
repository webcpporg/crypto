// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// AES-GCM's asynchronous functions, async_make, async_seal and async_open, on one backend
// (BearSSL, or OpenSSL where the program defines WEBCPP_TEST_ASYNC_GCM_OPENSSL), on a callback
// and in a coroutine:
// - async_spec_cases: the 18 cases of the specification through async_make, async_seal and
//   async_open give the synchronous answers byte for byte (ciphertext, tag, plaintext), the
//   completion arriving after the initiating call returned.
// - async_wrong_tag: a wrong tag completes with authentication_failed and zeroed data.
// - async_long_iv: a 129-byte IV completes with invalid_iv_size, the data untouched, for the
//   seal (with a zeroed tag) and the open.
// - async_make_refused: a 31-byte key completes with invalid_key_size and an empty gcm, which
//   refuses every member with invalid_state (review focus 5).
// - async_destroyed: the object destroyed after the initiating call and before the completion
//   still completes with the synchronous result (the work ran before the call returned).
// - async_coroutine: the example of async.hpp's header, in a coroutine of the context.

#include <webcpp/crypto/async.hpp>
#if defined(WEBCPP_TEST_ASYNC_GCM_OPENSSL)
#include <webcpp/crypto/backends/openssl.hpp>
#else
#include <webcpp/crypto/backends/bearssl.hpp>
#endif
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_spec_vectors.hpp"
#include "support/hex.hpp"

#include <webcpp/asio/as_tuple.hpp>
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
#include <utility>
#include <vector>

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;

namespace {

#if defined(WEBCPP_TEST_ASYNC_GCM_OPENSSL)
using backend = crypto::backends::openssl;
#else
using backend = crypto::backends::bearssl;
#endif

template <std::size_t KeySize>
struct cipher_of;

template <>
struct cipher_of<16> {
    using type = crypto::ciphers::aes128<backend>;
};

template <>
struct cipher_of<24> {
    using type = crypto::ciphers::aes192<backend>;
};

template <>
struct cipher_of<32> {
    using type = crypto::ciphers::aes256<backend>;
};

using gcm256 = crypto::ciphers::gcm<cipher_of<32>::type>;

bool all_zero(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

bool same_bytes(std::span<std::uint8_t const> left, std::span<std::uint8_t const> right) {
    return std::ranges::equal(left, right);
}

// What one completion handed over.
template <class Value>
struct completion {
    int calls = 0;
    boost::system::error_code code;
    std::optional<Value> value;
};

// Runs a start with a callback taking the code and a Value, checks that the completion did not
// come inside the call and came once after, and returns it.
template <class Value, class Start>
completion<Value> complete(asio::io_context& context, Start start) {
    completion<Value> done;
    bool returned = false;
    bool inline_call = false;
    start(context.get_executor(),
          [&done, &returned, &inline_call](boost::system::error_code code, Value value) {
              ++done.calls;
              inline_call = !returned;
              done.code = code;
              done.value.emplace(std::move(value));
          });
    returned = true;
    BOOST_TEST_EQ(done.calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(!inline_call);
    return done;
}

// The same for an operation without a value.
struct plain_completion {
    int calls = 0;
    boost::system::error_code code;
};

template <class Start>
plain_completion complete_plain(asio::io_context& context, Start start) {
    plain_completion done;
    bool returned = false;
    bool inline_call = false;
    start(context.get_executor(), [&done, &returned, &inline_call](boost::system::error_code code) {
        ++done.calls;
        inline_call = !returned;
        done.code = code;
    });
    returned = true;
    BOOST_TEST_EQ(done.calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(!inline_call);
    return done;
}

// One case of the specification, through the three functions, for the cipher of its key's size.
template <class Gcm>
void run_case(asio::io_context& context, webcpp::test::gcm_case const& spec) {
    auto const key = webcpp::test::from_hex(spec.key);
    auto const iv = webcpp::test::from_hex(spec.iv);
    auto const additional_data = webcpp::test::from_hex(spec.additional_data);
    auto const plaintext = webcpp::test::from_hex(spec.plaintext);
    auto const ciphertext = webcpp::test::from_hex(spec.ciphertext);
    auto const tag = webcpp::test::from_hex(spec.tag);

    auto made = complete<Gcm>(context, [&](auto const& executor, auto&& token) {
        crypto::async_make<Gcm>(executor, key, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!made.code);
    if (!BOOST_TEST(made.value.has_value()) || made.code) {
        return;
    }
    Gcm& aead = *made.value;

    std::vector<std::uint8_t> data = plaintext;
    auto sealed =
        complete<typename Gcm::result_type>(context, [&](auto const& executor, auto&& token) {
            crypto::async_seal(executor, aead, iv, additional_data, data,
                               std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!sealed.code);
    BOOST_TEST(same_bytes(data, ciphertext));
    if (BOOST_TEST(sealed.value.has_value())) {
        BOOST_TEST(same_bytes(std::span(sealed.value->data(), sealed.value->size()), tag));
    }

    auto const opened = complete_plain(context, [&](auto const& executor, auto&& token) {
        crypto::async_open(executor, aead, iv, additional_data, data, tag,
                           std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!opened.code);
    BOOST_TEST(same_bytes(data, plaintext));
}

void async_spec_cases(asio::io_context& context) {
    for (auto const& spec : webcpp::test::gcm_spec_cases) {
        switch (spec.key.size() / 2) {
            case 16: run_case<crypto::ciphers::gcm<cipher_of<16>::type>>(context, spec); break;
            case 24: run_case<crypto::ciphers::gcm<cipher_of<24>::type>>(context, spec); break;
            default: run_case<gcm256>(context, spec); break;
        }
    }
}

// A keyed gcm of the all-zero key, through async_make.
gcm256 keyed(asio::io_context& context) {
    std::array<std::uint8_t, 32> const key{};
    auto made = complete<gcm256>(context, [&](auto const& executor, auto&& token) {
        crypto::async_make<gcm256>(executor, key, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!made.code);
    BOOST_TEST(made.value.has_value());
    return std::move(*made.value);
}

void async_wrong_tag(asio::io_context& context) {
    gcm256 aead = keyed(context);
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 4> const additional_data{1, 2, 3, 4};
    std::array<std::uint8_t, 40> data{};
    data.fill(0x5a);
    auto sealed = complete<gcm256::result_type>(context, [&](auto const& executor, auto&& token) {
        crypto::async_seal(executor, aead, iv, additional_data, data,
                           std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!sealed.code);
    if (!BOOST_TEST(sealed.value.has_value())) {
        return;
    }
    std::array<std::uint8_t, 16> tag{};
    std::ranges::copy(*sealed.value, tag.begin());
    tag[7] ^= 1U;
    auto const opened = complete_plain(context, [&](auto const& executor, auto&& token) {
        crypto::async_open(executor, aead, iv, additional_data, data, tag,
                           std::forward<decltype(token)>(token));
    });
    BOOST_TEST(opened.code == crypto::error::authentication_failed);
    BOOST_TEST(all_zero(data));
}

void async_long_iv(asio::io_context& context) {
    gcm256 aead = keyed(context);
    std::array<std::uint8_t, 129> const iv{};
    std::array<std::uint8_t, 40> data{};
    data.fill(0x6c);
    auto const untouched = data;
    std::array<std::uint8_t, 16> const tag{};
    auto sealed = complete<gcm256::result_type>(context, [&](auto const& executor, auto&& token) {
        crypto::async_seal(executor, aead, iv, {}, data, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(sealed.code == crypto::error::invalid_iv_size);
    BOOST_TEST(same_bytes(data, untouched));
    if (BOOST_TEST(sealed.value.has_value())) {
        BOOST_TEST(all_zero(std::span(sealed.value->data(), sealed.value->size())));
    }
    auto const opened = complete_plain(context, [&](auto const& executor, auto&& token) {
        crypto::async_open(executor, aead, iv, {}, data, tag, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(opened.code == crypto::error::invalid_iv_size);
    BOOST_TEST(same_bytes(data, untouched));
}

void async_make_refused(asio::io_context& context) {
    std::array<std::uint8_t, 31> const key{};
    auto made = complete<gcm256>(context, [&](auto const& executor, auto&& token) {
        crypto::async_make<gcm256>(executor, key, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(made.code == crypto::error::invalid_key_size);
    if (!BOOST_TEST(made.value.has_value())) {
        return;
    }
    // The empty gcm refuses every member, and leaves data untouched.
    gcm256& empty = *made.value;
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 16> data{};
    data.fill(0x6c);
    auto const untouched = data;
    std::array<std::uint8_t, 16> const tag{};
    BOOST_TEST(empty.seal(iv, {}, data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.open(iv, {}, data, tag).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_seal(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_open(iv, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.result().error() == crypto::error::invalid_state);
    BOOST_TEST(same_bytes(data, untouched));
    // Through the asynchronous functions too.
    auto sealed = complete<gcm256::result_type>(context, [&](auto const& executor, auto&& token) {
        crypto::async_seal(executor, empty, iv, {}, data, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(sealed.code == crypto::error::invalid_state);
    BOOST_TEST(same_bytes(data, untouched));
}

// The example of async.hpp's header, in a coroutine of the context: make, seal, open.
// The object and the key destroyed after the initiating call and before the completion: a
// synchronous backend has sealed already, so the tag and the ciphertext are the synchronous ones.
void async_destroyed(asio::io_context& context) {
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 4> const additional_data{1, 2, 3, 4};
    std::array<std::uint8_t, 40> data{};
    data.fill(0x5a);
    auto expected_data = data;
    gcm256::result_type expected_tag{};
    {
        gcm256 reference = keyed(context);
        auto const sealed = reference.seal(iv, additional_data, expected_data);
        if (!BOOST_TEST(sealed.has_value())) {
            return;
        }
        expected_tag = *sealed;
    }
    gcm256::result_type tag{};
    boost::system::error_code code;
    {
        gcm256 aead = keyed(context);
        crypto::async_seal(context.get_executor(), aead, iv, additional_data, data,
                           [&](boost::system::error_code done_code, gcm256::result_type done) {
                               code = done_code;
                               tag = done;
                           });
    }
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(!code);
    BOOST_TEST(data == expected_data);
    BOOST_TEST(tag == expected_tag);
}

void async_coroutine(asio::io_context& context) {
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const executor = co_await asio::this_coro::executor;
            std::array<std::uint8_t, 32> const key{};
            std::array<std::uint8_t, 12> const iv{};
            std::array<std::uint8_t, 4> const additional_data{9, 8, 7, 6};
            std::array<std::uint8_t, 40> data{};
            data.fill(0x33);
            auto const plaintext = data;
            auto [made_code, aead] = co_await crypto::async_make<gcm256>(
                executor, key, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!made_code);
            auto [code, tag] = co_await crypto::async_seal(
                executor, aead, iv, additional_data, data, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!code);
            BOOST_TEST(!same_bytes(data, plaintext));
            auto [open_code] = co_await crypto::async_open(executor, aead, iv, additional_data,
                                                           data, std::span(tag.data(), tag.size()),
                                                           asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!open_code);
            BOOST_TEST(same_bytes(data, plaintext));
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
}

}  // namespace

int main() {
    asio::io_context context;
    async_spec_cases(context);
    async_wrong_tag(context);
    async_long_iv(context);
    async_make_refused(context);
    async_destroyed(context);
    async_coroutine(context);
    return webcpp::test::exit_status(boost::report_errors());
}
