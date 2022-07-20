/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
#include <iostream>
#include <unordered_map>

#include "oidc_credentials.h"
#include "tdf_client.h"
#include "nanotdf_client.h"
#include "tdf_exception.h"

int main() {

    using namespace virtru;

    // These are the credentials of OpenTDF backend when run locally
    constexpr auto OIDC_ENDPOINT = "http://localhost:65432/";
    constexpr auto KAS_URL = "http://localhost:65432/api/kas";
    constexpr auto CLIENT_ID = "tdf-client";
    constexpr auto CLIENT_SECRET = "123-456";
    constexpr auto ORGANIZATION_NAME = "tdf";
    std::string samplePlainTxt{"Virtru"};

    try {

        OIDCCredentials clientCreds;
        clientCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                     ORGANIZATION_NAME, OIDC_ENDPOINT);

        // Test NanoTDF
        {
            auto nanoTDFClient = std::make_unique<NanoTDFClient>(clientCreds, KAS_URL);

            TDFStorageType encryptStringType;
            encryptStringType.setTDFStorageStringType(samplePlainTxt);
            auto cipherText = nanoTDFClient->encryptData(encryptStringType);

            TDFStorageType decryptStringType;
            decryptStringType.setTDFStorageBufferType(cipherText);
            auto plainText = nanoTDFClient->decryptData(decryptStringType);
            std::string plainTextStr(plainText.begin(), plainText.end());

            if (samplePlainTxt == plainTextStr) {
                std::cout << "NanoTDF test passed!!" << std::endl;
            } else {
                std::cerr << "NanoTDF test failed!!" << std::endl;
                return EXIT_FAILURE;
            }
        }

        // Test TDF3
        {
            auto client = std::make_unique<TDFClient>(clientCreds, KAS_URL);

            TDFStorageType encryptStringType;
            encryptStringType.setTDFStorageStringType(samplePlainTxt);
            auto encryptedText = client->encryptData(encryptStringType);

            TDFStorageType decryptBufferType;
            decryptBufferType.setTDFStorageBufferType(encryptedText);
            auto plainTextAfterDecrypt = client->decryptData(decryptBufferType);
            std::string plainTextStr(plainTextAfterDecrypt.begin(), plainTextAfterDecrypt.end());

            if (samplePlainTxt == plainTextStr) {
                std::cout << "TDF3 test passed!!" << std::endl;
            } else {
                std::cerr << "TDF3 test failed!!" << std::endl;
                return EXIT_FAILURE;
            }
        }
    } catch (const Exception &exception) {
        std ::cerr << "virtru exception " << exception.what() << std::endl;
        return EXIT_FAILURE;
    } catch (const std::exception &exception) {
        std ::cerr << exception.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std ::cerr << "Unknown..." << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
