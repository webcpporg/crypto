// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The types aes128_gcm, aes256_gcm and gcm<aes256<>> name: AES-GCM's default backend, natively
// OpenSSL and on WebAssembly BearSSL, whatever is linked (design D32); aes256<> names the block
// cipher's own, natively OpenSSL and on WebAssembly ctaes (design D3). test/Jamfile builds this
// file once per combination of linked backends. The backends' headers are stand-ins from
// test/support/fake_backends, included first under the real headers' guards, so nothing here
// needs a real backend, and nothing is called: only the types' backends are read.

// clang-format off
#include "support/fake_backends/webcpp/crypto/backends/bearssl.hpp"
#include "support/fake_backends/webcpp/crypto/backends/openssl.hpp"
// clang-format on

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <type_traits>

#ifndef WEBCPP_TEST_FAKE_BACKEND
#error "the real backend headers were included, not test/support/fake_backends"
#endif

namespace crypto = webcpp::crypto;

#ifdef WEBCPP_CRYPTO_WEBASSEMBLY
using expected = crypto::backends::bearssl;
using block_expected = crypto::backends::ctaes;
#else
using expected = crypto::backends::openssl;
using block_expected = crypto::backends::openssl;
#endif

static_assert(std::is_same_v<crypto::default_backend, expected>);
static_assert(std::is_same_v<crypto::ciphers::aes256<>::backend_type, block_expected>);
static_assert(
    std::is_same_v<crypto::ciphers::gcm<crypto::ciphers::aes256<>>::backend_type, expected>);
static_assert(std::is_same_v<crypto::ciphers::aes256_gcm::backend_type, expected>);
static_assert(std::is_same_v<crypto::ciphers::aes128_gcm::backend_type, expected>);
