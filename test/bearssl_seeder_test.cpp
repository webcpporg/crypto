// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// BearSSL's own seeder is getentropy on every target but Windows, where it has none
// (spec sections 4.1, 6 and 8.4): no backend chooses its entropy. Where there is one, it seeds
// a generator: it returns 1, and two generators it seeds draw different bytes.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
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
    if (seeder == nullptr) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    std::array<br_hmac_drbg_context, 2> generators{};
    std::array<std::array<std::uint8_t, 32>, 2> drawn{};
    for (std::size_t i = 0; i < generators.size(); ++i) {
        br_hmac_drbg_init(&generators[i], &br_sha256_vtable, nullptr, 0);
        BOOST_TEST_EQ(seeder(&generators[i].vtable), 1);
        br_hmac_drbg_generate(&generators[i], drawn[i].data(), drawn[i].size());
    }
    BOOST_TEST(drawn[0] != drawn[1]);
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
