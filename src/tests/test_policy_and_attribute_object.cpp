//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/09.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_policy_object_suite

#include "policy_object.h"
#include "attribute_object.h"
#include "tdf_exception.h"

#include <string>
#include <iostream>

#include <boost/test/included/unit_test.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>


BOOST_AUTO_TEST_SUITE(test_policy_and_attribute_object_suite)

    using namespace virtru;
    BOOST_AUTO_TEST_CASE(test_policy_object_simple_test)
    {
        constexpr auto user1 = "user1@example.com";
        constexpr auto user2 = "user2@example.com";

        // Test the construction of the policy object.
        auto policyObject = PolicyObject{};
        policyObject.addDissem(user1);
        policyObject.addDissem(user2);

        // NOTE: Not sure we want to check if the dissem is always the
        // email address could be cert CN
//        constexpr auto invalidUser = "USER2@EXAMPLECOM";
//        try {
//            policyObject.addDissem(invalidUser);
//            BOOST_FAIL("We should not get here - invalid email address");
//        } catch ( const virtru::Exception& exception) {
//            BOOST_TEST_MESSAGE("Expected virtru exception.");
//            std :: cout << exception.what() << std::endl;
//        } catch ( ... ) {
//            BOOST_FAIL("Virtru exception should be thrown" );
//            std :: cout << "...\n";
//        }

        auto dissems = policyObject.getDissems();
        BOOST_CHECK(dissems.size() == 2);

        if (dissems.find(user1) == dissems.end()) {
            BOOST_FAIL("user1@example.com is missing from dissems.");
        }

        if (dissems.find(user2) == dissems.end()) {
            BOOST_FAIL("user2@example.com is missing from dissems.");
        }

        BOOST_TEST(to_string(boost::uuids::random_generator{}()).size(), policyObject.getUuid().size());
        BOOST_TEST_MESSAGE(policyObject.toJsonString(true));

        constexpr auto policyObjectStr = "{\n"
                                         "  \"body\": {\n"
                                         "      \"dissem\": [\n"
                                         "        \"someuser@example.com\"\n"
                                         "      ],\n"
                                         "    \"dataAttributes\": []\n"
                                         "  },\n"
                                         "  \"uuid\": \"6d9bedfa-e389-4b8a-895d-cb72902ea77f\"\n"
                                         "}";


        auto policyObject2 = PolicyObject::CreatePolicyObjectFromJson(policyObjectStr);

        auto dissems2 = policyObject2.getDissems();
        if (dissems2.find("someuser@example.com") == dissems2.end()) {
            BOOST_FAIL("someuser@example.com is missing from dissems.");
        }
        
        BOOST_TEST(policyObject2.getUuid().data() == "6d9bedfa-e389-4b8a-895d-cb72902ea77f");
    }

    BOOST_AUTO_TEST_CASE(test_policy_object_with_attribute_object)
    {
        constexpr auto owner = "owner@example.com";
        constexpr auto ownerFriend = "user1@example.com";
        constexpr auto attribute = "https://example.com/attr/Classification";
        constexpr auto displayName = "classification";
        constexpr auto pubKey = "-----BEGIN PUBLIC KEY-----\n"
                                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\n"
                                "2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\n"
                                "DJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\n"
                                "wd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\n"
                                "vvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\n"
                                "sZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\n"
                                "qQIDAQAB\n"
                                "-----END PUBLIC KEY-----";
        constexpr auto kasURL = "https://kas.example.com/";

        // Test the construction of the policy object.
        auto policyObject = PolicyObject{};
        policyObject.addDissem(owner);
        policyObject.addDissem(ownerFriend);

        auto attributeObject = AttributeObject{attribute, displayName, pubKey, kasURL, true};
        policyObject.addAttributeObject(attributeObject);
        policyObject.addAttributeObject(attributeObject);

        auto attributeObjectJsonStr = attributeObject.toJsonString(true);
        AttributeObject attributeObject2{attributeObjectJsonStr};
        BOOST_TEST(attributeObject2.getAttribute().data() == attribute);
        BOOST_TEST(attributeObject2.getDisplayName().data() == displayName);
        BOOST_TEST(attributeObject2.getKasPublicKey().data() == pubKey);
        BOOST_TEST(attributeObject2.getKasBaseUrl().data() == kasURL);
        BOOST_TEST(attributeObject2.isDefault() == true);

        BOOST_TEST_MESSAGE(attributeObject.toJsonString(true));

        auto dissems2 = policyObject.getDissems();
        if (dissems2.find(owner) == dissems2.end()) {
            BOOST_FAIL("owner is missing from dissems.");
        }

        if (dissems2.find(ownerFriend) == dissems2.end()) {
            BOOST_FAIL("owner friend is missing from dissems.");
        }
        
        BOOST_TEST(to_string(boost::uuids::random_generator{}()).size() == policyObject.getUuid().size());

        BOOST_TEST_MESSAGE(policyObject.toJsonString(true));

        const auto policyObjectStr1 = R"({
            "body": {
                "dissem": [
                "owner@example.com",
                        "user1@example.com"
                ],
                "dataAttributes": [
                {
                    "attribute": "https://example.com/attr/Classification",
                     "displayName": "classification",
                      "kasUrl": "https://kas.example.com/",
                      "pubKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\nqQIDAQAB\n-----END PUBLIC KEY-----",
                      "isDefault": true
                },
                {
                    "attribute": "https://example.com/attr/Classification",
                    "displayName": "classification",
                    "kasUrl": "https://kas.example.com/",
                    "pubKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\nqQIDAQAB\n-----END PUBLIC KEY-----"
                }
                ]
            },
            "uuid": "c1e22740-3dea-4f02-a021-effd75c2f9ba"
        })";

        std::cout << "Policy Object is" << policyObjectStr1 << std::endl;

        auto policyObject2 = PolicyObject::CreatePolicyObjectFromJson(policyObjectStr1);

        auto dissems3 = policyObject2.getDissems();
        if (dissems3.find(owner) == dissems3.end()) {
            BOOST_FAIL("owner is missing from dissems.");
        }

        if (dissems3.find(ownerFriend) == dissems3.end()) {
            BOOST_FAIL("owner Friend is missing from dissems.");
        }
        
        BOOST_TEST(to_string(boost::uuids::random_generator{}()).size() == policyObject2.getUuid().size());

        auto attributeObject3 = policyObject2.getAttributeObjects().back();
        BOOST_TEST(attributeObject3.getAttribute().data() == attribute);
        BOOST_TEST(attributeObject3.getDisplayName().data() == displayName);
        BOOST_TEST(attributeObject3.getKasPublicKey().data() == pubKey);
        BOOST_TEST(attributeObject3.getKasBaseUrl().data() == kasURL);
        BOOST_TEST(attributeObject3.isDefault() == false);

        auto attributeObject4 = policyObject2.getAttributeObjects().front();
        BOOST_TEST(attributeObject4.isDefault() == true);
    }

    // we check for reqired elements
    BOOST_AUTO_TEST_CASE(test_policy_object_negative_test)
    {
        try {
            constexpr auto invalidPolicyStr = "{\n"
                                              "  \"body\": {\n"
                                              "    \"body\": {\n"
                                              "      \"dissem\": [\n"
                                              "        \"someuser@example.com\"\n"
                                              "      ]\n"
                                              "    } \n"
                                              "  },\n"
                                              "  \"uuid\": \"6d9bedfa-e389-4b8a-895d-cb72902ea77f\"\n"
                                              "}";
            auto policyObject = PolicyObject::CreatePolicyObjectFromJson(invalidPolicyStr);
            BOOST_FAIL("We should not get here, should throw exception");

        } catch ( const virtru::Exception& exception) {
            std :: cout << exception.what() << std::endl;
        }
    }


BOOST_AUTO_TEST_SUITE_END()
