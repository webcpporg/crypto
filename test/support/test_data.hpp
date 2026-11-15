// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_TEST_DATA_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_TEST_DATA_HPP

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace webcpp::test {

/** The whole file at path; a test whose data is missing ends, naming it. */
inline std::string read_file(std::string const& path) {
    std::ifstream const in(path, std::ios::binary);
    if (!in) {
        static_cast<void>(std::fprintf(stderr, "cannot read %s\n", path.c_str()));
        std::exit(1);
    }
    std::ostringstream all;
    all << in.rdbuf();
    return all.str();
}

}  // namespace webcpp::test

#endif
