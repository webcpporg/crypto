// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// libsodium's secret boxes, crypto_secretbox (XSalsa20-Poly1305) and
// crypto_secretbox_xchacha20poly1305, through their default types, ciphers::secretbox<> and
// ciphers::secretbox_xchacha20poly1305<>, whose backend is libsodium on every target: NaCl's
// case of libsodium's test/default/secretbox.c and .exp and libsodium's XChaCha20 cases of
// test/default/xchacha20.c, every guard, tampering, moves, empty inputs and aliasing spans of
// support/aead_checks.hpp that apply to a family without additional data, which refuses a
// non-empty one with invalid_input_size. Their limit, 2^64 - 17 bytes, no span reaches.

#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <sodium/crypto_secretbox.h>  // its MESSAGEBYTES_MAX

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace crypto = webcpp::crypto;

namespace {

using secretbox = crypto::ciphers::secretbox<>;
using secretbox_xchacha = crypto::ciphers::secretbox_xchacha20poly1305<>;

// The default is libsodium on every target, the one backend of both families, and the types
// name their family and their algorithm as the capability table does.
static_assert(
    std::is_same_v<crypto::default_backend_t<crypto::families::secretbox_xsalsa20poly1305>,
                   crypto::backends::sodium>);
static_assert(
    std::is_same_v<crypto::default_backend_t<crypto::families::secretbox_xchacha20poly1305>,
                   crypto::backends::sodium>);
static_assert(
    std::is_same_v<secretbox, crypto::ciphers::aead<crypto::families::secretbox_xsalsa20poly1305,
                                                    crypto::backends::sodium>>);
static_assert(std::is_same_v<secretbox_xchacha,
                             crypto::ciphers::aead<crypto::families::secretbox_xchacha20poly1305,
                                                   crypto::backends::sodium>>);
static_assert(std::is_same_v<secretbox::family_type, crypto::families::secretbox_xsalsa20poly1305>);
static_assert(std::is_same_v<secretbox::name_type, crypto::families::secretbox_xsalsa20poly1305>);
static_assert(crypto::supports_v<secretbox, crypto::backends::sodium>);
static_assert(crypto::supports_v<secretbox_xchacha, crypto::backends::sodium>);
static_assert(secretbox::key_size == 32 && secretbox::iv_size == 24 && secretbox::tag_size == 16);
static_assert(secretbox_xchacha::key_size == 32 && secretbox_xchacha::iv_size == 24 &&
              secretbox_xchacha::tag_size == 16);
static_assert(secretbox::max_message_size == ~std::uint64_t{0} - 16);
// libsodium's own limit on a 64-bit target; on a 32-bit one libsodium's is the smaller,
// 2^32 - 17, as the Doc Comment says.
// NOLINTBEGIN(bugprone-branch-clone): libsodium's limit is its SODIUM_MIN macro, a ?: whose two
// operands are the same value on 64-bit Linux.
static_assert(sizeof(std::size_t) != 8 ||
              secretbox::max_message_size == crypto_secretbox_MESSAGEBYTES_MAX);
static_assert(sizeof(std::size_t) == 8 || crypto_secretbox_MESSAGEBYTES_MAX == 0xffffffffU - 16);
// NOLINTEND(bugprone-branch-clone)
static_assert(secretbox::max_additional_data_size == 0 &&
              secretbox_xchacha::max_additional_data_size == 0);

/**
 * NaCl's secret box, libsodium's test/default/secretbox.c: its key ("firstkey"), nonce and
 * the 131 bytes after the 32 zero bytes of its message; secretbox.exp prints the tag, then the
 * ciphertext, once sealed apart and once in place.
 */
constexpr std::array<webcpp::test::aead_case, 1> secretbox_cases{
    webcpp::test::aead_case{
        .key = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389",
        .iv = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
        .additional_data = "",
        .plaintext =
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac7"
            "28d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556a"
            "d6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f9377638"
            "48645e0705",
        .ciphertext =
            "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7"
            "f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368"
            "517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb4"
            "5a74e355a5",
        .tag = "f3ffc7703f9400e52a7dfb4b3d3305d9",
    },
};

/**
 * libsodium's XChaCha20 secret boxes, test/default/xchacha20.c's tv_secretbox_xchacha20poly1305:
 * its first, second and seventh cases (an empty message among them), each tag the first 16
 * bytes of the case's output and the ciphertext the rest. The first carries a message: the
 * checks tamper with it.
 */
constexpr std::array<webcpp::test::aead_case, 3> secretbox_xchacha_cases{
    webcpp::test::aead_case{
        .key = "d3c71d54e6b13506e07aa2e7b412a17a7a1f34df3d3148cd3f45b91ccaa5f4d9",
        .iv = "943b454a853aa514c63cf99b1e197bbb99da24b2e2d93e47",
        .additional_data = "",
        .plaintext = "76bd706e07741e713d90efdb34ad202067263f984942aae8bda159f30dfccc72200f8093520b"
                     "85c5ad124ff7c8b2d920946e5cfff4b819abf84c7b35a6205ca72c9f8747c3044dd73fb4beb"
                     "da1b476",
        .ciphertext = "1c6f526d2c19557cf8bd270fcde43fba1d88890663f7b2f5c6b1d7deccf5c91b4df5865dc55c"
                      "c7e04d6793fc2db8f9e3b418f95cb796d67a7f3f7e097150cb607c435dacf82eac3d669866e"
                      "5092ace",
        .tag = "0384276f1cfa5c82c3e58f0f2acc1f82",
    },
    webcpp::test::aead_case{
        .key = "065ff46a9dddb1ab047ee5914d6d575a828b8cc1f454b24e8cd0f57efdc49a34",
        .iv = "f83262646ce01293b9923a65a073df78c54b2e799cd6c4e5",
        .additional_data = "",
        .plaintext = "",
        .ciphertext = "",
        .tag = "4c72340416339dcdea01b760db5adaf7",
    },
    webcpp::test::aead_case{
        .key = "10c0ad4054b48d7d1de1d9ab6f782ca883d886573e9d18c1d47b6ee6b5208189",
        .iv = "977edf57428d0e0247a3c88c9a9ec321bbaae1a4da8353b5",
        .additional_data = "",
        .plaintext = "518e4a27949812424b2a381c3efea6055ee5e75eff",
        .ciphertext = "b05a15f8edb68b35773e81ac2aca18e9be53416f9a",
        .tag = "0c801a037c2ed0500d6ef68e8d195ece",
    },
};

}  // namespace

int main() {
    webcpp::test::check_aead<secretbox>(secretbox_cases);
    webcpp::test::check_aead<secretbox_xchacha>(secretbox_xchacha_cases);
    return webcpp::test::exit_status(boost::report_errors());
}
