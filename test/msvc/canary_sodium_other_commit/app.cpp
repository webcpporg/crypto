// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Initialises libsodium through the backend's header, which reads libsodium's canary, built for
// another commit than this program names: the link fails (LNK2038 on MSVC).
#include <webcpp/crypto/backends/sodium.hpp>

int main() {
    return webcpp::crypto::detail::sodium_ready() ? 0 : 1;
}
