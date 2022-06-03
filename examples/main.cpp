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
            auto cipherText = nanoTDFClient->encryptString(samplePlainTxt);
            auto plainText = nanoTDFClient->decryptString(cipherText);

            if (samplePlainTxt == plainText) {
                std::cout << "NanoTDF test passed!!" << std::endl;
            } else {
                std::cerr << "NanoTDF test failed!!" << std::endl;
                return EXIT_FAILURE;
            }
        }

        // Test NanoTDF
        {
            auto nanoTDFClient = std::make_unique<NanoTDFClient>(clientCreds, KAS_URL);
            auto cipherText = nanoTDFClient->encryptString(samplePlainTxt);
            auto plainText = nanoTDFClient->decryptString(cipherText);

            if (samplePlainTxt == plainText) {
                std::cout << "NanoTDF test passed!!" << std::endl;
            } else {
                std::cerr << "NanoTDF test failed!!" << std::endl;
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
