// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_WINDOWS_HPP
#define WEBCPP_CRYPTO_DETAIL_WINDOWS_HPP

#include <webcpp/crypto/config.hpp>

#ifdef _WIN32

// <windows.h> without NOMINMAX defines min and max as macros, which break every max()
// after it, and without WIN32_LEAN_AND_MEAN brings winsock.h, which clashes with a later
// winsock2.h (Boost.Asio's). Each is defined here only when the program has not, and
// undefined again only when defined here: a program that wants the macros includes
// <windows.h> itself first, and its include guard makes this one add nothing.
#ifndef NOMINMAX
#define NOMINMAX
#define WEBCPP_CRYPTO_DETAIL_DEFINED_NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#define WEBCPP_CRYPTO_DETAIL_DEFINED_WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>  // lint-world: BCryptGenRandom, this header's purpose

#include <bcrypt.h>  // lint-world: BCryptGenRandom, Windows' one generator

#ifdef WEBCPP_CRYPTO_DETAIL_DEFINED_NOMINMAX
#undef NOMINMAX
#undef WEBCPP_CRYPTO_DETAIL_DEFINED_NOMINMAX
#endif
#ifdef WEBCPP_CRYPTO_DETAIL_DEFINED_WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#undef WEBCPP_CRYPTO_DETAIL_DEFINED_WIN32_LEAN_AND_MEAN
#endif

#endif  // _WIN32

#endif  // WEBCPP_CRYPTO_DETAIL_WINDOWS_HPP
