//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/07.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_crypto_utils

#include "crypto_utils.h"
#include "bytes.h"
#include "tdf_exception.h"

#include <string>
#include <iostream>
#include <chrono>
#include <ctime>

#include <boost/type_index.hpp>
#include <boost/test/included/unit_test.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>

namespace vc = virtru::crypto;
using namespace std::string_literals;

void testBase64(const std::string& in, const std::string& out);

BOOST_AUTO_TEST_SUITE(test_crypto_utils_suite)

    // OpenSSL command
    // $echo -n "HelloWorld" | openssl dgst -sha256
    // (stdin)= 872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4
    constexpr std::string_view simpleString = "HelloWorld";
    const auto simpleStringOpenSSLOutput = "872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4"s;
    const auto sha256HashAsBase64 = "hy5OUM6ZkNiwQTMMR8nd0Rvsa1A66ThqmdqFhOm7EsQ="s;

    // $ ls -la 2MBofXChar.txt -rw-r--r--@ 1 SReddy  staff  2097152 Mar 13 13:56 2MBofXChar.txt
    // $ more 2MBofXChar.txt | openssl dgst -sha256
    //(stdin)= 4689a79943566678fcb6c278d5d219848f85df420e88349ab7e20937390068b5
    const auto twoMBBufferOpenSSLOutput = "4689a79943566678fcb6c278d5d219848f85df420e88349ab7e20937390068b5"s;


    // HMAC secret
    constexpr std::string_view secret = "secret";

    // $ echo -n "HelloWorld" | openssl dgst -sha256 -hmac "secret"
    //(stdin)= 2e91612bb72b29d82f32789d063de62d5897a4ee5d3b5d34459801b94397b099
    const auto simpleStringHMACOpenSSLOutput = "2e91612bb72b29d82f32789d063de62d5897a4ee5d3b5d34459801b94397b099"s;

    // $ more 2MBofXChar.txt | openssl dgst -sha256 -hmac "secret"
    //(stdin)= 347117193af6eeccf0d967cae3e105a1c53fc7c0294263356e651590984f544e
    const auto twoMBBufferHMACOpenSSLOutput = "347117193af6eeccf0d967cae3e105a1c53fc7c0294263356e651590984f544e"s;

    BOOST_AUTO_TEST_CASE(test_crypto_utils_sha256) {
        // simple test
        auto value = vc::hexHashSha256(vc::toBytes(simpleString));
        BOOST_TEST(value == simpleStringOpenSSLOutput);

        value = vc::base64HashSha256(vc::toBytes(simpleString));
        BOOST_TEST(value == sha256HashAsBase64);

        // advance test
        // Big buffer of 2MB to see if performance is still under 10 milliseconds.
        constexpr auto twoMBSize = 2 * 1024 * 1024;
		std::vector<char> twoMbBuffer(twoMBSize);
		std::fill(twoMbBuffer.begin(), twoMbBuffer.end(), 'X');

        auto t1 = std::chrono::high_resolution_clock::now();
        auto value1 = vc::hexHashSha256(vc::toBytes(twoMbBuffer));
        auto t2 = std::chrono::high_resolution_clock::now();
        auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        BOOST_TEST(value1 == twoMBBufferOpenSSLOutput);

        std::cout << "hexHashSha256() took " << timeSpent << " milliseconds to calculate sha256 for 2MB data"
                  << std::endl;
        
        twoMbBuffer.resize(0);
        auto emptyStringHash = vc::hexHashSha256(vc::toBytes(twoMbBuffer));
        BOOST_TEST(emptyStringHash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    BOOST_AUTO_TEST_CASE(test_crypto_utils_hmac_sha256) {

        // HMAC Tests
        auto value = vc::hexHmacSha256(vc::toBytes(simpleString), vc::toBytes(secret));
        BOOST_TEST(value == simpleStringHMACOpenSSLOutput);

        // advance test
        // Big buffer of 2MB to see if performance is still under 10 milliseconds.
		constexpr auto twoMBSize = 2 * 1024 * 1024;
		std::vector<char> twoMbBuffer(twoMBSize);
		std::fill(twoMbBuffer.begin(), twoMbBuffer.end(), 'X');

        auto t1 = std::chrono::high_resolution_clock::now();
        auto value1 = vc::hexHmacSha256(vc::toBytes(twoMbBuffer), vc::toBytes(secret));
        auto t2 = std::chrono::high_resolution_clock::now();
        auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        BOOST_TEST(value1 == twoMBBufferHMACOpenSSLOutput);

        std::cout << "hexHmacSha256() took " << timeSpent << " milliseconds to calculate hmac sha256 for 2MB data"
                  << std::endl;
    }

    BOOST_AUTO_TEST_CASE(test_crypto_utils_symmetric_key) {

        using boost::typeindex::type_id_with_cvr;

        // symmetricKey Tests
        constexpr auto keySize16 = 16ul;
        auto symmetricKey1 = vc::symmetricKey<keySize16>();
        BOOST_TEST(symmetricKey1.size() == keySize16);

        std::cout << "symmetricKey1 is of type = "
             << type_id_with_cvr<decltype(symmetricKey1)>().pretty_name()
             << '\n';
        //std::string symmetricKey1Str(reinterpret_cast<const char*>(symmetricKey1.data()));
        //std::cout << "16 bytes symmetricKey as binary: " << symmetricKey1Str << std::endl;
        std::cout << "16 bytes symmetricKey as HEX: " << vc::hex(vc::toBytes(symmetricKey1)) << std::endl;

        // symmetricKey Tests
        constexpr auto keySize64 = 64ul;
        auto symmetricKey2 = vc::symmetricKey<keySize64>();
        BOOST_TEST(symmetricKey2.size() == keySize64);
    }


    BOOST_AUTO_TEST_CASE(test_crypto_utils_base64_encode_decode) {

        // $ openssl enc -base64 <<< 'Hello, World!'
        // SGVsbG8sIFdvcmxkIQo=
        const auto input1 = "Hello, World!"s;
        const auto output1 = "SGVsbG8sIFdvcmxkIQ=="s;

        // Bytes version
        auto encodedStr1 = vc::base64Encode(vc::toBytes(input1));
        auto decodedStr1 = vc::base64Decode(vc::toBytes(output1));
        BOOST_TEST(encodedStr1 == output1);
        BOOST_TEST(decodedStr1 == input1);

        // std::string version
        auto encodedStr2 = vc::base64Encode(input1);
        auto decodedStr2 = vc::base64Decode(output1);
        BOOST_TEST(encodedStr2 == output1);
        BOOST_TEST(decodedStr2 == input1);

        testBase64 ("",       "");
        testBase64 ("f",      "Zg==");
        testBase64 ("fo",     "Zm8=");
        testBase64 ("foo",    "Zm9v");
        testBase64 ("foob",   "Zm9vYg==");
        testBase64 ("fooba",  "Zm9vYmE=");
        testBase64 ("foobar", "Zm9vYmFy");
    }


BOOST_AUTO_TEST_SUITE_END()

void testBase64(const std::string& in, const std::string& out) {

    // Bytes version
    auto const encoded1 = vc::base64Encode(vc::toBytes(in));
    BOOST_TEST(encoded1 == out);
    BOOST_TEST(vc::base64Decode(vc::toBytes(encoded1)) == in);

    // std::string version
    auto const encoded2 = vc::base64Encode(in);
    BOOST_TEST(encoded2 == out);
    BOOST_TEST(vc::base64Decode(encoded2) == in);
}
