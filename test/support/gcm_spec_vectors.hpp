// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_GCM_SPEC_VECTORS_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_GCM_SPEC_VECTORS_HPP

#include <array>
#include <string_view>

namespace webcpp::test {

/** One case of the GCM specification, in hex. */
struct gcm_case {
    std::string_view key, plaintext, additional_data, iv, ciphertext, tag;
};

/** The 18 cases of the GCM specification (McGrew and Viega, appendix B), 1 to 18 in order. */
inline constexpr std::array<gcm_case, 18> gcm_spec_cases{
    {
        {
            .key = "00000000000000000000000000000000",
            .plaintext = "",
            .additional_data = "",
            .iv = "000000000000000000000000",
            .ciphertext = "",
            .tag = "58e2fccefa7e3061367f1d57a4e7455a",
        },
        {
            .key = "00000000000000000000000000000000",
            .plaintext = "00000000000000000000000000000000",
            .additional_data = "",
            .iv = "000000000000000000000000",
            .ciphertext = "0388dace60b6a392f328c2b971b2fe78",
            .tag = "ab6e47d42cec13bdf53a67b21257bddf",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b391aafd255",
            .additional_data = "",
            .iv = "cafebabefacedbaddecaf888",
            .ciphertext = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b2"
                          "5466931c7d8f6a5aac84a"
                          "a051ba30b396a0aac973d58e091473f5985",
            .tag = "4d5c2af327cd64a62cf35abd2ba6fab4",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "cafebabefacedbaddecaf888",
            .ciphertext = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b2"
                          "5466931c7d8f6a5aac84a"
                          "a051ba30b396a0aac973d58e091",
            .tag = "5bc94fbc3221a5db94fae95ae7121a47",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "cafebabefacedbad",
            .ciphertext = "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900"
                          "e49f24b22b097544d4896"
                          "b424989b5e1ebac0f07c23f4598",
            .tag = "3612d2e79e3b0785561be14aaca2fccb",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539"
                  "fcf0e2429a6b5"
                  "25416aedbf5a0de6a57a637b39b",
            .ciphertext = "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4"
                          "fba43c90ccdcb281d48c7"
                          "c6fd62875d2aca417034c34aee5",
            .tag = "619cc5aefffe0bfa462af43c1699d050",
        },
        {
            .key = "000000000000000000000000000000000000000000000000",
            .plaintext = "",
            .additional_data = "",
            .iv = "000000000000000000000000",
            .ciphertext = "",
            .tag = "cd33b28ac773f74ba00ed1f312572435",
        },
        {
            .key = "000000000000000000000000000000000000000000000000",
            .plaintext = "00000000000000000000000000000000",
            .additional_data = "",
            .iv = "000000000000000000000000",
            .ciphertext = "98e7247c07f0fe411c267e4384b0f600",
            .tag = "2ff58d80033927ab8ef4d4587514f0fb",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b391aafd255",
            .additional_data = "",
            .iv = "cafebabefacedbaddecaf888",
            .ciphertext = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00"
                          "c144c525ac619d18c84a3"
                          "f4718e2448b2fe324d9ccda2710acade256",
            .tag = "9924a7c8587336bfb118024db8674a14",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "cafebabefacedbaddecaf888",
            .ciphertext = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00"
                          "c144c525ac619d18c84a3"
                          "f4718e2448b2fe324d9ccda2710",
            .tag = "2519498e80f1478f37ba55bd6d27618c",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "cafebabefacedbad",
            .ciphertext = "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df"
                          "9a471f75c66541d4d4dad"
                          "1c9e93a19a58e8b473fa0f062f7",
            .tag = "65dcc57fcf623a24094fcca40d3533f8",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539"
                  "fcf0e2429a6b5"
                  "25416aedbf5a0de6a57a637b39b",
            .ciphertext = "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012"
                          "af34ddd9e2f037589b292"
                          "db3e67c036745fa22e7e9b7373b",
            .tag = "dcf566ff291c25bbb8568fc3d376a6d9",
        },
        {
            .key = "0000000000000000000000000000000000000000000000000000000000000000",
            .plaintext = "",
            .additional_data = "",
            .iv = "000000000000000000000000",
            .ciphertext = "",
            .tag = "530f8afbc74536b9a963b4f1c4cb738b",
        },
        {
            .key = "0000000000000000000000000000000000000000000000000000000000000000",
            .plaintext = "00000000000000000000000000000000",
            .additional_data = "",
            .iv = "000000000000000000000000",
            .ciphertext = "cea7403d4d606b6e074ec5d3baf39d18",
            .tag = "d0d1c8a799996bf0265b98b5d48ab919",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b391aafd255",
            .additional_data = "",
            .iv = "cafebabefacedbaddecaf888",
            .ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48"
                          "590dbb3da7b08b1056828"
                          "838c5f61e6393ba7a0abcc9f662898015ad",
            .tag = "b094dac5d93471bdec1a502270e3cc6c",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "cafebabefacedbaddecaf888",
            .ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48"
                          "590dbb3da7b08b1056828"
                          "838c5f61e6393ba7a0abcc9f662",
            .tag = "76fc6ece0f4e1768cddf8853bb2d551b",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "cafebabefacedbad",
            .ciphertext = "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d3"
                          "3934a4f0954cc2363bc73"
                          "f7862ac430e64abe499f47c9b1f",
            .tag = "3a337dbf46a792c45e454913fe2ea8f2",
        },
        {
            .key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            .plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
                         "56809532fcf0e2449a6b"
                         "525b16aedf5aa0de657ba637b39",
            .additional_data = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            .iv = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539"
                  "fcf0e2429a6b5"
                  "25416aedbf5a0de6a57a637b39b",
            .ciphertext = "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b7"
                          "80f244452da3ebf1c5d82"
                          "cdea2418997200ef82e44ae7e3f",
            .tag = "a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
        },
    },
};

}  // namespace webcpp::test

#endif
