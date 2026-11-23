// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// AES-GCM's asynchronous functions, async_from_key, async_seal and async_open, on one backend
// (BearSSL, or OpenSSL where the program defines WEBCPP_TEST_ASYNC_GCM_OPENSSL), on a callback
// and in a coroutine:
// - async_spec_cases: the 18 cases of the specification through async_from_key, async_seal and
//   async_open give the synchronous answers byte for byte (ciphertext, tag, plaintext), the
//   completion arriving after the initiating call returned.
// - async_wrong_tag: a wrong tag completes with authentication_failed and zeroed data.
// - async_long_iv: a 129-byte IV completes with invalid_nonce_size, the data untouched, for the
//   seal (with a zeroed tag) and the open.
// - async_from_key_refused: a 31-byte key completes with invalid_key_size and an empty gcm, which
//   refuses every member with invalid_state (review focus 5).
// - async_destroyed: the object destroyed after the initiating call and before the completion
//   still completes with the synchronous result (the work ran before the call returned).
// - async_coroutine: the example of async.hpp's header, in a coroutine of the context.
// - async_four_forms: each operation in its four forms (design D9), the member and the free,
//   synchronous and asynchronous, gives the same result: from_key (the same seal, and the same
//   refusal of a short key), seal (the same ciphertext and tag), open (the plaintext, and a
//   changed tag's authentication_failed with zeroed data); each asynchronous completion arrives
//   after the initiating call returned.
// - async_member_deferred: aead.async_seal with asio::deferred runs when launched, after the
//   call returned, and gives the synchronous seal's ciphertext and tag.

#include <webcpp/crypto/async.hpp>
#ifdef WEBCPP_TEST_ASYNC_GCM_OPENSSL
#include <webcpp/crypto/backends/openssl.hpp>
#else
#include <webcpp/crypto/backends/bearssl.hpp>
#endif
#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_spec_vectors.hpp"
#include "support/hex.hpp"

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/deferred.hpp>
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

#ifdef WEBCPP_TEST_ASYNC_GCM_OPENSSL
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
    auto const nonce = webcpp::test::from_hex(spec.nonce);
    auto const associated_data = webcpp::test::from_hex(spec.associated_data);
    auto const plaintext = webcpp::test::from_hex(spec.plaintext);
    auto const ciphertext = webcpp::test::from_hex(spec.ciphertext);
    auto const tag = webcpp::test::from_hex(spec.tag);

    auto made = complete<Gcm>(context, [&](auto const& executor, auto&& token) {
        crypto::async_from_key<Gcm>(executor, key, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!made.code);
    if (!BOOST_TEST(made.value.has_value()) || made.code) {
        return;
    }
    Gcm& aead = *made.value;

    std::vector<std::uint8_t> data = plaintext;
    auto sealed =
        complete<typename Gcm::result_type>(context, [&](auto const& executor, auto&& token) {
            crypto::async_seal(executor, aead, nonce, associated_data, data,
                               std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!sealed.code);
    BOOST_TEST(same_bytes(data, ciphertext));
    if (BOOST_TEST(sealed.value.has_value())) {
        BOOST_TEST(same_bytes(std::span(sealed.value->data(), sealed.value->size()), tag));
    }

    auto const opened = complete_plain(context, [&](auto const& executor, auto&& token) {
        crypto::async_open(executor, aead, nonce, associated_data, data, tag,
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

// A keyed gcm of the all-zero key, through async_from_key.
gcm256 keyed(asio::io_context& context) {
    std::array<std::uint8_t, 32> const key{};
    auto made = complete<gcm256>(context, [&](auto const& executor, auto&& token) {
        crypto::async_from_key<gcm256>(executor, key, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!made.code);
    BOOST_TEST(made.value.has_value());
    return std::move(*made.value);
}

void async_wrong_tag(asio::io_context& context) {
    gcm256 aead = keyed(context);
    std::array<std::uint8_t, 12> const nonce{};
    std::array<std::uint8_t, 4> const associated_data{1, 2, 3, 4};
    std::array<std::uint8_t, 40> data{};
    data.fill(0x5a);
    auto sealed = complete<gcm256::result_type>(context, [&](auto const& executor, auto&& token) {
        crypto::async_seal(executor, aead, nonce, associated_data, data,
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
        crypto::async_open(executor, aead, nonce, associated_data, data, tag,
                           std::forward<decltype(token)>(token));
    });
    BOOST_TEST(opened.code == crypto::error::authentication_failed);
    BOOST_TEST(all_zero(data));
}

void async_long_iv(asio::io_context& context) {
    gcm256 aead = keyed(context);
    std::array<std::uint8_t, 129> const nonce{};
    std::array<std::uint8_t, 40> data{};
    data.fill(0x6c);
    auto const untouched = data;
    std::array<std::uint8_t, 16> const tag{};
    auto sealed = complete<gcm256::result_type>(context, [&](auto const& executor, auto&& token) {
        crypto::async_seal(executor, aead, nonce, {}, data, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(sealed.code == crypto::error::invalid_nonce_size);
    BOOST_TEST(same_bytes(data, untouched));
    if (BOOST_TEST(sealed.value.has_value())) {
        BOOST_TEST(all_zero(std::span(sealed.value->data(), sealed.value->size())));
    }
    auto const opened = complete_plain(context, [&](auto const& executor, auto&& token) {
        crypto::async_open(executor, aead, nonce, {}, data, tag,
                           std::forward<decltype(token)>(token));
    });
    BOOST_TEST(opened.code == crypto::error::invalid_nonce_size);
    BOOST_TEST(same_bytes(data, untouched));
}

void async_from_key_refused(asio::io_context& context) {
    std::array<std::uint8_t, 31> const key{};
    auto made = complete<gcm256>(context, [&](auto const& executor, auto&& token) {
        crypto::async_from_key<gcm256>(executor, key, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(made.code == crypto::error::invalid_key_size);
    if (!BOOST_TEST(made.value.has_value())) {
        return;
    }
    // The empty gcm refuses every member, and leaves data untouched.
    gcm256& empty = *made.value;
    std::array<std::uint8_t, 12> const nonce{};
    std::array<std::uint8_t, 16> data{};
    data.fill(0x6c);
    auto const untouched = data;
    std::array<std::uint8_t, 16> const tag{};
    BOOST_TEST(empty.seal(nonce, {}, data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.open(nonce, {}, data, tag).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_seal(nonce, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.begin_open(nonce, {}).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.update(data).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.result().error() == crypto::error::invalid_state);
    BOOST_TEST(same_bytes(data, untouched));
    // Through the asynchronous functions too.
    auto const sealed = complete<gcm256::result_type>(context, [&](auto const& executor,
                                                                   auto&& token) {
        crypto::async_seal(executor, empty, nonce, {}, data, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(sealed.code == crypto::error::invalid_state);
    BOOST_TEST(same_bytes(data, untouched));
}

// The example of async.hpp's header, in a coroutine of the context: from_key, seal, open.
// The object and the key destroyed after the initiating call and before the completion: a
// synchronous backend has sealed already, so the tag and the ciphertext are the synchronous ones.
void async_destroyed(asio::io_context& context) {
    std::array<std::uint8_t, 12> const nonce{};
    std::array<std::uint8_t, 4> const associated_data{1, 2, 3, 4};
    std::array<std::uint8_t, 40> data{};
    data.fill(0x5a);
    auto expected_data = data;
    gcm256::result_type expected_tag{};
    {
        gcm256 reference = keyed(context);
        auto const sealed = reference.seal(nonce, associated_data, expected_data);
        if (!BOOST_TEST(sealed.has_value())) {
            return;
        }
        expected_tag = *sealed;
    }
    gcm256::result_type tag{};
    boost::system::error_code code;
    {
        gcm256 aead = keyed(context);
        crypto::async_seal(context.get_executor(), aead, nonce, associated_data, data,
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
            std::array<std::uint8_t, 12> const nonce{};
            std::array<std::uint8_t, 4> const associated_data{9, 8, 7, 6};
            std::array<std::uint8_t, 40> data{};
            data.fill(0x33);
            auto const plaintext = data;
            auto made_code_result = co_await crypto::async_from_key<gcm256>(
                executor, key, asio::as_tuple(asio::use_awaitable));
            auto& [made_code, aead] = made_code_result;
            BOOST_TEST(!made_code);
            auto [code, tag] = co_await crypto::async_seal(
                executor, aead, nonce, associated_data, data, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!code);
            BOOST_TEST(!same_bytes(data, plaintext));
            auto [open_code] = co_await crypto::async_open(executor, aead, nonce, associated_data,
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

// What the four forms of an AES-GCM test share: the key, the IV, the additional data and the
// message.
struct four_forms_message {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 4> associated_data{1, 2, 3, 4};
    std::array<std::uint8_t, 40> plaintext{};

    four_forms_message() {
        for (std::size_t index = 0; index < key.size(); ++index) {
            key[index] = static_cast<std::uint8_t>((index * 7U) + 1U);
        }
        nonce.fill(0x24);
        plaintext.fill(0x5a);
    }
};

// The ciphertext and tag one form of seal gave.
struct sealed_message {
    boost::system::error_code code;
    std::array<std::uint8_t, 40> data{};
    gcm256::result_type tag{};
};

// from_key in its four forms: objects that seal alike, and the same refusal of a short key.
void four_forms_from_key(asio::io_context& context, four_forms_message const& message) {
    auto const member_sync = gcm256::from_key(message.key);
    auto const free_sync = crypto::from_key<gcm256>(message.key);
    auto member_async = complete<gcm256>(context, [&](auto const& executor, auto&& token) {
        return gcm256::async_from_key(executor, message.key, std::forward<decltype(token)>(token));
    });
    auto free_async = complete<gcm256>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_from_key<gcm256>(executor, message.key,
                                              std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!member_async.code);
    BOOST_TEST(!free_async.code);
    if (!BOOST_TEST(member_sync.has_value()) || !BOOST_TEST(free_sync.has_value()) ||
        !BOOST_TEST(member_async.value.has_value()) || !BOOST_TEST(free_async.value.has_value())) {
        return;
    }
    // Each object seals the message as the first does.
    auto const tag_of = [&message](gcm256 aead) {
        auto data = message.plaintext;
        auto const sealed = aead.seal(message.nonce, message.associated_data, data);
        BOOST_TEST(sealed.has_value());
        return sealed ? *sealed : gcm256::result_type{};
    };
    auto expected = gcm256::from_key(message.key);
    if (!BOOST_TEST(expected.has_value())) {
        return;
    }
    auto const tag = tag_of(std::move(*expected));
    BOOST_TEST(!all_zero(std::span(tag.data(), tag.size())));
    BOOST_TEST(tag_of(std::move(*member_async.value)) == tag);
    BOOST_TEST(tag_of(std::move(*free_async.value)) == tag);
    auto const short_key = std::span(message.key).first(31);
    BOOST_TEST(gcm256::from_key(short_key).error() == crypto::error::invalid_key_size);
    BOOST_TEST(crypto::from_key<gcm256>(short_key).error() == crypto::error::invalid_key_size);
    BOOST_TEST(complete<gcm256>(context, [&](auto const& executor, auto&& token) {
                   return gcm256::async_from_key(executor, short_key,
                                                 std::forward<decltype(token)>(token));
               }).code == crypto::error::invalid_key_size);
    BOOST_TEST(complete<gcm256>(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_from_key<gcm256>(executor, short_key,
                                                         std::forward<decltype(token)>(token));
               }).code == crypto::error::invalid_key_size);
}

// seal in its four forms, each on a fresh copy of the message.
std::array<sealed_message, 4> four_seals(asio::io_context& context, gcm256& aead,
                                         four_forms_message const& message) {
    std::array<sealed_message, 4> sealed{};
    for (auto& one : sealed) {
        one.data = message.plaintext;
    }
    auto const keep = [](sealed_message& one, boost::system::result<gcm256::result_type> done) {
        one.code = done ? boost::system::error_code{} : done.error();
        if (done) {
            one.tag = *done;
        }
    };
    keep(sealed[0], aead.seal(message.nonce, message.associated_data, sealed[0].data));
    keep(sealed[1], crypto::secret_key_encryption::aead::seal(
                        aead, message.nonce, message.associated_data, sealed[1].data));
    auto const member_async =
        complete<gcm256::result_type>(context, [&](auto const& executor, auto&& token) {
            return aead.async_seal(executor, message.nonce, message.associated_data, sealed[2].data,
                                   std::forward<decltype(token)>(token));
        });
    auto const free_async =
        complete<gcm256::result_type>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_seal(executor, aead, message.nonce, message.associated_data,
                                      sealed[3].data, std::forward<decltype(token)>(token));
        });
    sealed[2].code = member_async.code;
    sealed[3].code = free_async.code;
    if (BOOST_TEST(member_async.value.has_value()) && BOOST_TEST(free_async.value.has_value())) {
        sealed[2].tag = *member_async.value;
        sealed[3].tag = *free_async.value;
    }
    return sealed;
}

// open in its four forms, each of a fresh copy of `ciphertext`: the same answer, and the
// plaintext or zeros.
void check_four_opens(asio::io_context& context, gcm256& aead, four_forms_message const& message,
                      std::array<std::uint8_t, 40> const& ciphertext,
                      std::span<std::uint8_t const> tag, boost::system::error_code expected_code) {
    std::array<std::array<std::uint8_t, 40>, 4> data{
        ciphertext,
        ciphertext,
        ciphertext,
        ciphertext,
    };
    auto const code_of = [](boost::system::result<void> const& done) {
        return done ? boost::system::error_code{} : done.error();
    };
    BOOST_TEST(code_of(aead.open(message.nonce, message.associated_data, data[0], tag)) ==
               expected_code);
    BOOST_TEST(code_of(crypto::secret_key_encryption::aead::open(
                   aead, message.nonce, message.associated_data, data[1], tag)) == expected_code);
    BOOST_TEST(complete_plain(context, [&](auto const& executor, auto&& token) {
                   return aead.async_open(executor, message.nonce, message.associated_data, data[2],
                                          tag, std::forward<decltype(token)>(token));
               }).code == expected_code);
    BOOST_TEST(complete_plain(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_open(executor, aead, message.nonce, message.associated_data,
                                             data[3], tag, std::forward<decltype(token)>(token));
               }).code == expected_code);
    for (auto const& opened : data) {
        if (expected_code) {
            BOOST_TEST(all_zero(opened));
        } else {
            BOOST_TEST(opened == message.plaintext);
        }
    }
}

void async_member_deferred(asio::io_context& context) {
    four_forms_message const message;
    auto aead = gcm256::from_key(message.key);
    if (!BOOST_TEST(aead.has_value())) {
        return;
    }
    auto expected_data = message.plaintext;
    auto const expected_tag = aead->seal(message.nonce, message.associated_data, expected_data);
    if (!BOOST_TEST(expected_tag.has_value())) {
        return;
    }
    auto data = message.plaintext;
    auto operation = aead->async_seal(context.get_executor(), message.nonce,
                                      message.associated_data, data, asio::deferred);
    // Nothing runs before the operation is launched.
    BOOST_TEST(data == message.plaintext);
    int calls = 0;
    std::move(operation)([&](boost::system::error_code code, gcm256::result_type tag) {
        ++calls;
        BOOST_TEST(!code);
        BOOST_TEST(tag == *expected_tag);
    });
    BOOST_TEST_EQ(calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(data == expected_data);
}

void async_four_forms(asio::io_context& context) {
    four_forms_message const message;
    four_forms_from_key(context, message);
    auto aead = gcm256::from_key(message.key);
    if (!BOOST_TEST(aead.has_value())) {
        return;
    }
    auto const sealed = four_seals(context, *aead, message);
    for (auto const& one : sealed) {
        BOOST_TEST(!one.code);
        BOOST_TEST(one.data == sealed[0].data);
        BOOST_TEST(one.tag == sealed[0].tag);
    }
    BOOST_TEST(sealed[0].data != message.plaintext);
    std::span<std::uint8_t const> const tag(sealed[0].tag.data(), sealed[0].tag.size());
    check_four_opens(context, *aead, message, sealed[0].data, tag, {});
    auto changed = sealed[0].tag;
    changed[7] ^= 1U;
    check_four_opens(context, *aead, message, sealed[0].data,
                     std::span<std::uint8_t const>(changed.data(), changed.size()),
                     crypto::error::authentication_failed);
}

}  // namespace

int main() {
    asio::io_context context;
    async_spec_cases(context);
    async_wrong_tag(context);
    async_long_iv(context);
    async_from_key_refused(context);
    async_destroyed(context);
    async_coroutine(context);
    async_four_forms(context);
    async_member_deferred(context);
    return webcpp::test::exit_status(boost::report_errors());
}
