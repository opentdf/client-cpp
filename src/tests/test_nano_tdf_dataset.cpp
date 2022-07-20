//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/09/24.
//  Copyright 2020 Virtru Corporation
//

#define BOOST_TEST_MODULE test_nano_tdf_dataset

#include "tdfbuilder.h"
#include "entity_object.h"
#include "crypto/rsa_key_pair.h"
#include "network_interface.h"
#include "nanotdf_dataset_client.h"
#include "network/http_client_service.h"

#include <random>
#include <iostream>
#include <sstream>
#include <memory>

#include <boost/test/included/unit_test.hpp>

using namespace virtru;
using namespace virtru::network;

#if RUN_BACKEND_TESTS
#define TEST_OIDC 1
#else
#define TEST_OIDC 0
#endif
constexpr auto OIDC_ENDPOINT = "http://localhost:65432/";
constexpr auto KAS_URL = "http://localhost:65432/api/kas";
constexpr auto CLIENT_ID = "tdf-client";
constexpr auto CLIENT_SECRET = "123-456";
constexpr auto ORGANIZATION_NAME = "tdf";


/// Generate a random string.
/// NOTE: Not really worried about the randomness of the string content.
std::string RandomString(size_t len) {
    std::string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string newstr;
    size_t pos;
    while(newstr.size() != len) {
        pos = ((rand() % (str.size() - 1)));
        newstr += str.substr(pos,1);
    }
    return newstr;
}

void testWithDataSetAndDistribution(size_t dataSetLenght, size_t low, size_t high, uint32_t iteration) {

    std::vector<std::string> dataSet(dataSetLenght);
    std::vector<std::string> dataSetEncrypted(dataSetLenght);
    std::vector<std::string> finalDataSet(dataSetLenght);

    // Fill the data set with random strings
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(low, high);
    for (auto & index : dataSet) {
        index = RandomString(dis(gen));
    }

    OIDCCredentials userCreds;
    userCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                 ORGANIZATION_NAME, OIDC_ENDPOINT);
    NanoTDFDatasetClient datasetClient{userCreds, KAS_URL, 2};
    //datasetClient.shareWithUsers({user});
    datasetClient.enableConsoleLogging(LogLevel::Warn);

    auto encryptTimeT1 = std::chrono::high_resolution_clock::now();

    // Encrypt the dataset
    for (size_t index = 0; index < dataSet.size(); index++) {
        auto tdfData = datasetClient.encryptString(dataSet[index]);
        std::string encryptedData{tdfData};
        dataSetEncrypted[index] = std::move(encryptedData);
    }

    auto encryptTimeT2 = std::chrono::high_resolution_clock::now();
    auto encryptTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(encryptTimeT2 - encryptTimeT1).count();
    std::cout  << "Encrypt - Data set count:" << dataSetLenght << " Time:" <<  encryptTimeSpent << " ms" << '\n';

    auto decryptTimeT1 = std::chrono::high_resolution_clock::now();

    // Decrypt the dataset
    for (size_t index = 0; index < dataSetEncrypted.size(); index++) {
        auto decryptedData = datasetClient.decryptString(dataSetEncrypted[index]);

        if (!decryptedData.empty()) {
            std::string decryptedText(reinterpret_cast<const char*>(&decryptedData[0]), decryptedData.size());
            finalDataSet[index] = std::move(decryptedText);
        } else {
            finalDataSet[index] = ""; // empty in and empty out.
        }
    }

    auto decryptTimeT2 = std::chrono::high_resolution_clock::now();
    auto decryptTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(decryptTimeT2 - decryptTimeT1).count();
    std::cout  << "Decrypt - Data set count:" << dataSetLenght << " Time:" <<  decryptTimeSpent << " ms" << '\n';

    // Test if the decrypt data is same as original
    for (size_t index = 0; index < dataSet.size(); index++) {
        BOOST_TEST(dataSet[index] == finalDataSet[index], "Success!!");
    }
}

BOOST_AUTO_TEST_SUITE(test_nano_tdf_dataset_suit)

    BOOST_AUTO_TEST_CASE(test_nan_tdf_dataset_simple)
    {
#if TEST_OIDC
        OIDCCredentials userCreds;
        userCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                   ORGANIZATION_NAME, OIDC_ENDPOINT);
        NanoTDFDatasetClient datasetClient{userCreds, KAS_URL};
        std::string plainText{"Virtru"};

        // encrypt the stream.
        auto tdfData = datasetClient.encryptString(plainText);

        std::string encryptedData{tdfData};
        auto decryptedData = datasetClient.decryptString(encryptedData);
        BOOST_TEST(plainText == decryptedData,  "TDF data decrypted successfully.");
#endif
    }

    BOOST_AUTO_TEST_CASE(test_nan_tdf_dataset_advanced) {
#if TEST_OIDC
        // Seed for RandomString() method.
        srand(time(0));

        testWithDataSetAndDistribution(10, 0, 1, 2);
        testWithDataSetAndDistribution(100, 1, 100, 20);
        testWithDataSetAndDistribution(500, 1, 100, 100);
        testWithDataSetAndDistribution(1000, 1, 1000, 500000);
#endif
    }

    BOOST_AUTO_TEST_CASE(test_nan_tdf_dataset_exception) {
#if TEST_OIDC
        try {
            std::string moreThan2MBString = RandomString(2097152 + 1);
            OIDCCredentials userCreds;
            userCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                       ORGANIZATION_NAME, OIDC_ENDPOINT);
            NanoTDFDatasetClient datasetClient{userCreds, KAS_URL};
            datasetClient.encryptString(moreThan2MBString);
            BOOST_FAIL("We should not get here");
        } catch (std::exception& e) {
            BOOST_TEST_MESSAGE("Expect exception");
            std::cout << "Standard exception: " << e.what() << '\n';
        } catch ( ... ) {
            BOOST_FAIL("Exception should be thrown" );
            std :: cout << "...\n";
        }
#endif
    }

#if 0

    BOOST_AUTO_TEST_CASE(test_nan_tdf_dataset_performace) {

        // Seed for RandomString() method.
        srand(time(0));

        OIDCCredentials userCreds;
        userCreds.setClientCredentials("tdf-client", "123-456",
                                       "tdf", OIDC_ENDPOINT);
        NanoTDFDatasetClient datasetClient{userCreds, KAS_URL};

        auto twombString = RandomString(2097152); // 2mb

        auto encryptTimeT1 = std::chrono::high_resolution_clock::now();
        size_t dataSet = 10000;
        for (size_t index = 0; index < dataSet ; index++) {
            auto bytes = datasetClient.encryptString(twombString);
        }

        auto encryptTimeT2 = std::chrono::high_resolution_clock::now();
        auto encryptTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(encryptTimeT2 - encryptTimeT1).count();
        std::cout  << "Encrypt - Data set count:" << dataSet << " Time:" <<  encryptTimeSpent << " ms" << '\n';
    }
#endif

BOOST_AUTO_TEST_SUITE_END()