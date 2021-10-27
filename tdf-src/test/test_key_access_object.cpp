//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/25.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_key_access_object_suite

#include "key_access_object.h"

#include <boost/test/included/unit_test.hpp>


BOOST_AUTO_TEST_SUITE(test_key_access_object_suite)

    using namespace virtru;
    BOOST_AUTO_TEST_CASE(test_key_access_object) {

        constexpr auto remoteKeyAccessType = "remote";
        constexpr auto wrappedKeyAccessType = "wrapped";
        constexpr auto defaultKasProtocol = "kas";
        constexpr auto kasUrl = "https://kas.example.com:5000";
        constexpr auto wrappedKey = "BzmgoIxZzMmIF42qzbdD4Rw30GtdaRSQL2Xlfms1OPs=";
        constexpr auto policyBindingHash = "BzmgoIxZzMmIF42qzbdD4Rw30GtdaRSQL2Xlfms1OPs=";
        constexpr auto encryptedMetadata = "ZoJTNW24UMhnXIif0mSnqLVCU=";

        auto keyAccessObject = KeyAccessObject{};

        keyAccessObject.setKasUrl(kasUrl);
        BOOST_TEST(keyAccessObject.getKasUrl() == kasUrl);
        BOOST_TEST(keyAccessObject.getKeyAccessTypeAsStr() == remoteKeyAccessType);
        BOOST_TEST(keyAccessObject.getProtocolAsStr() == defaultKasProtocol);

        keyAccessObject.setWrappedKey(wrappedKey);
        keyAccessObject.setPolicyBindingHash(policyBindingHash);
        keyAccessObject.setEncryptedMetadata(encryptedMetadata);

        auto keyAccessObjectAsJsonStr = keyAccessObject.toJsonString(true);

        auto keyAccessObject1 = KeyAccessObject::createKeyAccessObjectFromJson(keyAccessObjectAsJsonStr);
        std::cerr << "Key Access object as json str =" << keyAccessObjectAsJsonStr << std::endl;

        BOOST_TEST(keyAccessObject1.getWrappedKey() == wrappedKey);
        BOOST_TEST(keyAccessObject1.getPolicyBindingHash() == policyBindingHash);
        BOOST_TEST(keyAccessObject1.getEncryptedMetadata() == encryptedMetadata);

        if (keyAccessObject1.getKeyAccessType() != KeyAccessType::Remote) {
            BOOST_FAIL("Invalid key access type.");
        }

        if (keyAccessObject1.getProtocol() != KeyAccessProtocol::Kas) {
            BOOST_FAIL("Invalid key access protocol.");
        }

        auto keyAccessObject2 =  KeyAccessObject{};
        keyAccessObject2.setKasUrl(kasUrl);
        keyAccessObject2.setKeyAccessType(KeyAccessType::Wrapped);

        if (keyAccessObject2.getKeyAccessType() != KeyAccessType::Wrapped) {
            BOOST_FAIL("Invalid key access type.");
        }
        BOOST_TEST(keyAccessObject2.getKeyAccessTypeAsStr() == wrappedKeyAccessType);
    }
BOOST_AUTO_TEST_SUITE_END()