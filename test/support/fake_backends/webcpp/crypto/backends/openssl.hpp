// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A stand-in for the real openssl backend header, for default_selection_test.cpp alone: it
// completes the type that config.hpp declares, with the name the test reads, and nothing
// else. Only that test puts this directory on its include path.
#ifndef WEBCPP_TEST_FAKE_BACKENDS_OPENSSL_HPP
#define WEBCPP_TEST_FAKE_BACKENDS_OPENSSL_HPP

#include <webcpp/crypto/config.hpp>

#include <string_view>

namespace webcpp::crypto::backends {

struct openssl {
    static constexpr std::string_view name = "openssl";
};

}  // namespace webcpp::crypto::backends

#endif  // WEBCPP_TEST_FAKE_BACKENDS_OPENSSL_HPP
