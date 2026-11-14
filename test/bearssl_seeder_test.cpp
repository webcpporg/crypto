// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BearSSL's own seeder is getentropy on every target but Windows, where it has none
// (spec sections 4.1, 6 and 8.4): no backend chooses its entropy.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <string_view>

int main() {
    char const* name = nullptr;
    br_prng_seeder const seeder = br_prng_seeder_system(&name);
#ifdef _WIN32
    BOOST_TEST(seeder == nullptr);
    BOOST_TEST_EQ(std::string_view(name), "none");
#else
    BOOST_TEST(seeder != nullptr);
    BOOST_TEST_EQ(std::string_view(name), "getentropy");
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
