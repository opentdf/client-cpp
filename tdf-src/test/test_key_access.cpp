//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/09
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_key_access_suite

#include "key_access.h"
#include "key_access_object.h"
#include "policy_object.h"
#include "tdf_constants.h"
#include "splitkey_encryption.h"
#include "asym_encryption.h"
#include "bytes.h"
#include "crypto_utils.h"
#include "sdk_constants.h"
#include "asym_decryption.h"
#include "gcm_decryption.h"
#include "bytes.h"
#include "tdf_exception.h"

#include <tao/json.hpp>
#include <boost/test/included/unit_test.hpp>
#include <memory>

BOOST_AUTO_TEST_SUITE(test_key_access_suite)

    using namespace virtru;
    using namespace virtru::crypto;
    using namespace std::string_literals;

    const auto kasPublicKeyAsX509 = "-----BEGIN CERTIFICATE-----\n"
            "MIIDsjCCApqgAwIBAgIUZfE4NRP/EXOTi1BCHK+Ta/bL2RQwDQYJKoZIhvcNAQEM\n"
            "BQAwcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkRDMRMwEQYDVQQHDApXYXNoaW5n\n"
            "dG9uMQ8wDQYDVQQKDAZWaXJ0cnUxDDAKBgNVBAMMA2thczEgMB4GCSqGSIb3DQEJ\n"
            "ARYRZGV2b3BzQHZpcnRydS5jb20wIBcNMTgxMDI2MDUxNDAxWhgPMzAxODAyMjYw\n"
            "NTE0MDFaMHAxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJEQzETMBEGA1UEBwwKV2Fz\n"
            "aGluZ3RvbjEPMA0GA1UECgwGVmlydHJ1MQwwCgYDVQQDDANrYXMxIDAeBgkqhkiG\n"
            "9w0BCQEWEWRldm9wc0B2aXJ0cnUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
            "MIIBCgKCAQEA0hHeLffSYfIMF/MNj0I23fi/zhRjAwCfu1bwooKi+L/DZbgX/bml\n"
            "42352QOwpAAZFnI/Ifp55+S1cBuFJFNfuqr3jg7AQPAgOX7XUnDBi1g9GjIyzgi7\n"
            "CEu+1kZKjqhgaEsUSvUyf7N7jjsyhJ/7CLOyxB0jhUd9xJfOTRVhplgQ8lhVLZoa\n"
            "E/NqBtpjxT3xG66ujouo0GT/UzvtiVL58kOHh2k5o8NU+NK0I/YYOJ5Qa+U9OMNi\n"
            "Y9CCUuiManA1rPuL6LqS/EfPwESqQ/g1rHzSSpFIxcZ3t69SHmeY2t1hMfVXP3GU\n"
            "vlYbl0tyd0+wEL/Cj9cUUOsx8ArxPbBQ9QIDAQABo0IwQDAdBgNVHQ4EFgQUPH1C\n"
            "MQsVyxmxUTx3O+cpQ1M84IEwHwYDVR0jBBgwFoAUPH1CMQsVyxmxUTx3O+cpQ1M8\n"
            "4IEwDQYJKoZIhvcNAQEMBQADggEBAEN4cToOwuQt5OLOdgiWpQtGJL1FYaecKPlZ\n"
            "NiFGyHP2RglcxKkBQK+ttO2BVa0P7Xtqi33pQzRvuyFYFbTJ1QG3GE6FfK/5jpIo\n"
            "Gjf/oj6X7EZ1jMvIUGmckzQhZ6zXCeCEil3mWTBGS9nKts+bbuBZtGxxuIBdr3DS\n"
            "RL26p6QaEKbRZAA41DrRfSiL3YjB7D54MkCueGnJz+BqHJCfrEl6sOSrDfE2kr8M\n"
            "00Q6g8+g61x1ItJxXaLsfx7CCZzww71cCf2LP5se+OotNYLjzvQhbQeVghxLbmNr\n"
            "3BEb4LGgiLOlxElZhho1Y5IotHcuRoQyLqvjIybEl9LZ8PUGV2A=\n"
            "-----END CERTIFICATE-----\n"s;

    constexpr auto kasUrl = "api.virtru.com";
    const std::string metaData = R"({"displayName" : "effective-c++.pdf"})";
    constexpr auto user1 = "user1@example.com";
    constexpr auto user2 = "user2@example.com";

    BOOST_AUTO_TEST_CASE(test_wrapped_key_access_basic) {

        constexpr auto keySize32 = 32ul;
        auto symmetricKey2 = symmetricKey<keySize32>();
        BOOST_TEST(symmetricKey2.size() == keySize32);

        // Test the construction of the policy object.
        auto policyObject = PolicyObject{};
        policyObject.addDissem(user1);
        policyObject.addDissem(user2);

        auto keyAccess = std::unique_ptr<KeyAccess>{std::make_unique<WrappedKeyAccess>(kasUrl, kasPublicKeyAsX509,
                                                                                       policyObject, metaData)};

        auto&& keyAccessObject = keyAccess->construct(symmetricKey2, metaData);

        BOOST_TEST(keyAccessObject.getKasUrl() == kasUrl);
        BOOST_TEST(keyAccessObject.getKeyAccessTypeAsStr() == kKeyAccessWrapped);
        BOOST_TEST(keyAccessObject.getProtocolAsStr() == kKasProtocol);
        BOOST_TEST_MESSAGE(keyAccessObject.toJsonString(true));
    }

    BOOST_AUTO_TEST_CASE(test_remote_key_access_basic) {

        constexpr auto keySize32 = 32ul;
        auto symmetricKey2 = symmetricKey<keySize32>();
        BOOST_TEST(symmetricKey2.size() == keySize32);

        // Test the construction of the policy object.
        auto policyObject = PolicyObject{};
        policyObject.addDissem(user1);
        policyObject.addDissem(user2);

        auto keyAccess = std::unique_ptr<KeyAccess>{std::make_unique<RemoteKeyAccess>(kasUrl, kasPublicKeyAsX509,
                                                                                      policyObject, metaData)};
        auto&& keyAccessObject = keyAccess->construct(symmetricKey2, metaData);

        BOOST_TEST(keyAccessObject.getKasUrl() == kasUrl);
        BOOST_TEST(keyAccessObject.getKeyAccessTypeAsStr() == kKeyAccessRemote);
        BOOST_TEST(keyAccessObject.getProtocolAsStr() == kKasProtocol);
        BOOST_TEST_MESSAGE(keyAccessObject.toJsonString(true));
    }

BOOST_AUTO_TEST_SUITE_END()
