// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The AES block cipher on its default backend, `aes128<>`, `aes192<>` and `aes256<>`, whose header
 it includes when the program links it: natively OpenSSL, on wasip2, wasip3 and Emscripten ctaes,
 whatever else the program links (`default_backend_t<families::aes_block>`). A program that uses
 them without linking the default stops where it calls them, with the Jamfile line that links it
 and the type that names another backend, as `aes256<backends::ctaes>`.

 On MSVC the source-built OpenSSL is compiled without assembly: its AES is table-driven, with no
 AES-NI, and not constant time. The default there is OpenSSL all the same, so a program that
 wants ctaes names `aes256<backends::ctaes>`.

 @see "The block cipher", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_AES_BLOCK_HPP
#define WEBCPP_CRYPTO_CIPHERS_AES_BLOCK_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/detail/defaults.hpp>

#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_AES_BLOCK_OPENSSL) && defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#include <webcpp/crypto/backends/openssl.hpp>
#elif defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_AES_BLOCK_CTAES) && defined(WEBCPP_CRYPTO_HAS_CTAES)
#include <webcpp/crypto/backends/ctaes.hpp>
#endif

#endif  // WEBCPP_CRYPTO_CIPHERS_AES_BLOCK_HPP
