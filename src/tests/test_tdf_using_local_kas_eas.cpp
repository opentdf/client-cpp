//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/04/16.
//  Copyright 2020 Virtru Corporation
//

#define BOOST_TEST_MODULE test_tdf_local_kas_eas

#include "tdf_client.h"
#include "tdf.h"
#include "nanotdf/ecc_mode.h"
#include "nanotdf_client.h"
#include "crypto/ec_key_pair.h"
#include "network/http_client_service.h"
#include "tdf_exception.h"
#include "crypto/rsa_key_pair.h"
#include "oidc_credentials.h"

#include <boost/test/included/unit_test.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/filesystem.hpp>
#include <iostream>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#define LOCAL_HOST 1
#define TEST_OIDC 0
#define LOCAL_EAS_KAS_SETUP 0
constexpr auto user = "user1";
constexpr auto user2 = "user2";
constexpr auto easUrl = "http://localhost:8000/";

#if LOCAL_HOST
constexpr auto OIDC_ENDPOINT = "http://localhost:65432/";
constexpr auto KAS_URL = "http://localhost:65432/kas";
constexpr auto CLIENT_ID = "tdf-client";
constexpr auto CLIENT_SECRET = "123-456";
constexpr auto ORGANIZATION_NAME = "tdf";
#else
constexpr auto OIDC_ENDPOINT = "https://keycloak.opentdf.us";
constexpr auto KAS_URL = "https://opentdf.us/kas";
constexpr auto CLIENT_ID = "test-entity-nonperson-00";
constexpr auto CLIENT_SECRET = "aa8fefd9-972e-4a6a-98e2-8f1a6a80c341";
constexpr auto ORGANIZATION_NAME = "opentdf-realm";
#endif


using namespace virtru::network;
using namespace virtru::crypto;
using namespace virtru::nanotdf;
using namespace virtru;

void test24BitBigEndian(std::uint32_t value) {

    using namespace boost::endian;

    // Save as big endian
    big_uint24_t bigEndianValueForWrite = value;
    std::array<std::uint8_t, sizeof(big_uint24_t)> buffer;
    std::memcpy(buffer.data(), &bigEndianValueForWrite, sizeof(big_uint24_t));

    static_assert(sizeof(big_uint24_t) == 3u);

    // Read as big endian and convert to native
    big_uint24_t bigEndianValueForRead{0};
    std::memcpy(&bigEndianValueForRead, buffer.data(), sizeof(big_uint24_t));
    std::uint32_t valueAsNative = bigEndianValueForRead;

    BOOST_TEST(value == valueAsNative);
}

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

std::string getCurrentWorkingDir() {
    char buff[FILENAME_MAX];
    GetCurrentDir( buff, FILENAME_MAX );
    std::string current_working_dir(buff);
    return current_working_dir;
}

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

void testTDFOperations(TDFClientBase* client) {
    std::string currentDir = getCurrentWorkingDir();

    // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
    std::string inPathEncrypt {currentDir };
            inPathEncrypt.append("\\data\\sample.pdf");

            std::string outPathEncrypt {currentDir };
            outPathEncrypt.append("\\data\\encrypt\\sample.pdf.tdf");

            std::string inPathDecrypt {currentDir };
            inPathDecrypt.append("\\data\\encrypt\\sample.pdf.tdf");

            std::string outPathDecrypt {currentDir };
            outPathDecrypt.append("\\data\\decrypt\\sample.pdf");
#else
    std::string inPathEncrypt{currentDir};
    inPathEncrypt.append("/data/sample.pdf");

    std::string outPathEncrypt{currentDir};
    outPathEncrypt.append("/data/encrypt/sample.pdf.tdf");

    std::string inPathDecrypt{currentDir};
    inPathDecrypt.append("/data/encrypt/sample.pdf.tdf");

    std::string outPathDecrypt{currentDir};
    outPathDecrypt.append("/data/decrypt/sample.pdf");
#endif

    client->encryptFile(inPathEncrypt, outPathEncrypt);

    std::cout << std::endl;
    client->decryptFile(inPathDecrypt, outPathDecrypt);

    BOOST_TEST_MESSAGE("TDF basic test passed.");
    std::array<std::uint32_t, 10u> bufferSizes{1, 10, 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024,
                                               8 * 1024 * 1024, (16 * 1024 * 1024 - 35), 100, 1000, 8000 };
    for (const auto& size : bufferSizes) {

        std::string plainText = RandomString(size);
        auto encryptedText = client->encryptString(plainText);
        auto plainTextAfterDecrypt = client->decryptString(encryptedText);
        BOOST_TEST(plainText == plainTextAfterDecrypt);
    }

    for (const auto& size : bufferSizes) {

        std::string plainText = RandomString(size);
        std::vector<uint8_t> text(plainText.begin(), plainText.end());
        auto encryptedText = client->encryptData(text);
        auto plainTextAfterDecrypt = client->decryptData(encryptedText);
        std::string decryptedText(plainTextAfterDecrypt.begin(), plainTextAfterDecrypt.end());
        BOOST_TEST(plainText == decryptedText);
    }
}

void testNanoTDFOperations(TDFClientBase* client1, NanoTDFClient* client2) {

    // IV - 3 bytes, Max Auth tag - 32 bytes, so total of 35 bytes overhead for the payload 
    std::array<std::uint32_t, 10u> fileSizeArray{0, 1, 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024,
                                                 8 * 1024 * 1024, (16 * 1024 * 1024 - 35), 100, 1000, 2000 };

    { // File tests with signature.

        for (const auto& size : fileSizeArray) {
            std::string plainText = RandomString(size);
            { // Write file
                std::ofstream f("nano_tdf_text.txt");
                f.write(plainText.data(), plainText.size());
            }

            client1->encryptFile("nano_tdf_text.txt", "nano_tdf_text.txt.ntdf");
            client1->decryptFile("nano_tdf_text.txt.ntdf", "nano_tdf_text_out.txt");

            std::string plainTextAfterDecrypt;
            { // Read file.
                std::ifstream inFile;
                inFile.open("nano_tdf_text_out.txt");

                std::stringstream strStream;
                strStream << inFile.rdbuf();
                plainTextAfterDecrypt = strStream.str();
            }

            BOOST_TEST(plainText == plainTextAfterDecrypt);
        }
    }

    { // Buffer test nano tdf.

        for (const auto& size : fileSizeArray) {

            std::string plainText = RandomString(size);
            auto encryptedText = client1->encryptString(plainText);
            auto plainTextAfterDecrypt = client2->decryptString(encryptedText);
            BOOST_TEST(plainText == plainTextAfterDecrypt);
        }
    }

    { // Buffer test nano tdf.

        for (const auto& size : fileSizeArray) {

            std::string plainText = RandomString(size);
            std::vector<uint8_t> text(plainText.begin(), plainText.end());
            auto encryptedText = client1->encryptData(text);
            auto plainTextAfterDecrypt = client2->decryptData(encryptedText);
            std::string decryptedText(plainTextAfterDecrypt.begin(), plainTextAfterDecrypt.end());
            BOOST_TEST(plainText == decryptedText);
        }
    }
}

BOOST_AUTO_TEST_SUITE(test_tdf_kas_eas_local_suite)

    using namespace virtru;

    BOOST_AUTO_TEST_CASE(test_nano_tdf_is_valid) {

        const auto nanoTDFSample1 = "TDFMARFldGhlcmlhLmxvY2FsL2thcwABAgBkgMMPt6NfC/Mg24Faij3jnLW1zQ2zivB"
                                    "qFmWwgav2R4z2h4kbt3yCwhR0nwUm7h60+l0eCkx4/TNnAlLNlSLlYo89eUKmS4jrR9"
                                    "tZH+RKsNYuPVs3cUB428DIkXA8cMNpJWty6MOQGx26mHPrAt7Dg2Ly47lOGIKntGqam"
                                    "DJRWatdAEzTToDzQ0SVCKPwAAAZAQAAAAAAAAAAAAAAFSgwnmFFkOHxUdgUKQ==";
        auto nanoTDFSample1AsBinary = base64Decode(nanoTDFSample1);
        BOOST_TEST(NanoTDFClient::isValidNanoTDFData(nanoTDFSample1AsBinary) == true);

        // Invalid protocol
        const auto badNanoTDFSample1 = "TDDMARFldGhlcmlhLmxvY2FsL2thcwABAgBkgMMPt6NfC/Mg24Faij3jnLW1zQ2zivB"
                                       "qFmWwgav2R4z2h4kbt3yCwhR0nwUm7h60+l0eCkx4/TNnAlLNlSLlYo89eUKmS4jrR9"
                                       "tZH+RKsNYuPVs3cUB428DIkXA8cMNpJWty6MOQGx26mHPrAt7Dg2Ly47lOGIKntGqam"
                                       "DJRWatdAEzTToDzQ0SVCKPwAAAZAQAAAAAAAAAAAAAAFSgwnmFFkOHxUdgUKQ==";
        auto badNanoTDFSample1AsBinary = base64Decode(badNanoTDFSample1);
        BOOST_TEST(NanoTDFClient::isValidNanoTDFData(badNanoTDFSample1AsBinary) == false);

        const auto nanoTDFWithSignature = "TDFMARFldGhlcmlhLmxvY2FsL2thcwCBAgBkl+QwXxiWGU2P8WDeVe9OJyWKKAKm5p0br+"
                                          "r3ytLPZxrVWd4CvoyPpTTHxOr6Bw0echHlKaHUkaQ/EyUp230cV2A39rutqzIrFCZ6ilQl"
                                          "C1UOBF8Gj0apefQ75zIFdjxbzA8+F7+wuRYP9tEUA2/S7IevIkipw64drL0SYW46sU4IaA"
                                          "8GLeTlC8dCfvBdAAAkAQAAAAAAAAAAAAAAvMJt2svJcvjiZIn+BxGIbmfA74adQouIA+UC"
                                          "9k5QomEfWwYHSj8f9E/y+fVwBCUufw7jp+D3eCu4DGzy8KZZPob0MKmKcIPTW27OoPAUus"
                                          "Pz0AKHYLQMmAbIRdzHa1FtSOAXhHMhB1ObJmteBxjfO8mUrWarqazeRw==";
        auto nanoTDFWithSignatureAsBinary = base64Decode(nanoTDFWithSignature);
        BOOST_TEST(NanoTDFClient::isValidNanoTDFData(nanoTDFWithSignatureAsBinary) == true);

        const auto invalidNanoTDFWithSignature = "TDFMARFldGhlcmlhLmxvY2FsL2thcwCBAgBkl+QwXxiWGU2P8WDeVe9OJyWKKAKm5p0br+"
                                                 "r3ytLPZxrVWd4CvoyPpTTHxOr6Bw0echHlKaHUkaQ/EyUp230cV2A39rutqzIrFCZ6ilQl"
                                                 "C1UOBF8Gj0apefQ75zIFdjxbzA8+F7+wuRYP9tEUA2/S7IevIkipw64drL0SYW46sU4IaA"
                                                 "8GLeTlC8dCfvBdAAAkAQAAAAAAAAAAAAAAvMJt2svJcvjiZIn+BxGIbmfA74adQouIA+UC"
                                                 "9k5QomEfWwYHSj8f9E/y+fVwBCUufw7jp+D3eCu4DGzy8KZZPob0MKmKcIPTW27OoPAUus"
                                                 "Pz0AKHYLQMmAbIRdzHa1FtSOAXhHMhB1ObJmteBxjfO8mUrWarzeRw==";
        auto invalidNanoTDFWithSignatureAsBinary = base64Decode(invalidNanoTDFWithSignature);
        BOOST_TEST(NanoTDFClient::isValidNanoTDFData(invalidNanoTDFWithSignatureAsBinary) == false);

        std::string currentDir = getCurrentWorkingDir();
#ifdef _WINDOWS
        std::string validNanoTDFFilePath {currentDir };
        validNanoTDFFilePath.append("\\data\\valid_nanotdf.ntdf");

        std::string invalidNanoTDFFilePath {currentDir };
        invalidNanoTDFFilePath.append("\\data\\invalid_nanotdf.ntdf");
#else
        std::string validNanoTDFFilePath {currentDir };
        validNanoTDFFilePath.append("/data/valid_nanotdf.ntdf");

        std::string invalidNanoTDFFilePath {currentDir };
        invalidNanoTDFFilePath.append("/data/invalid_nanotdf.ntdf");
#endif
        BOOST_TEST(NanoTDFClient::isValidNanoTDFFile(validNanoTDFFilePath) == true);
        BOOST_TEST(NanoTDFClient::isValidNanoTDFFile(invalidNanoTDFFilePath) == false);
        BOOST_TEST(NanoTDFClient::isValidNanoTDFData(invalidNanoTDFFilePath) == false);
    }

    BOOST_AUTO_TEST_CASE(test_old_version_nano_tdf) {
#if 0
        std::string currentDir = getCurrentWorkingDir();
#ifdef _WINDOWS
        std::string ntdfFilePath {currentDir };
        ntdfFilePath.append("\\data\\old_ver_nanotdf.ntdf");

        std::string outPathEncrypt {currentDir };
        outPathEncrypt.append("\\data\\decrypt\\old_ver_nanotdf.txt");
#else
        std::string ntdfFilePath {currentDir };
        ntdfFilePath.append("/data/old_ver_nanotdf.ntdf");

        std::string outPathEncrypt {currentDir };
        outPathEncrypt.append("/data/decrypt/old_ver_nanotdf.txt");
#endif
        NanoTDFClient client{easUrl, user};
        client.decryptFileUsingOldFormat(ntdfFilePath, outPathEncrypt);
#endif
    }

    BOOST_AUTO_TEST_CASE(test_tdf_kas_eas_local) {

        try {
#if TEST_OIDC

#if 0 // Enable once the PE authz is supported
            OIDCCredentials userCreds;
            userCreds.setUserCredentials("browsertest", "user1",
                                         "password", "tdf", OIDC_ENDPOINT);
            auto tdfOIDCClient = std::make_unique<TDFClient>(userCreds, KAS_URL);

            auto attributes = tdfOIDCClient->getSubjectAttributes();
            std::cout << "The subject attributes:" << std::endl;
            for(const auto& attribute: attributes) {
                std::cout << attribute << std::endl;
            }

            if (!attributes.empty()) {
                auto attribute = attributes.front();
                tdfOIDCClient->addDataAttribute(attribute, "");
            }

            // Test tdf with user creds
            testTDFOperations(tdfOIDCClient.get());

#endif

            OIDCCredentials clientCreds;
            clientCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                         ORGANIZATION_NAME, OIDC_ENDPOINT);
            auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds, KAS_URL);

            auto attributes = oidcClientTDF->getSubjectAttributes();
            std::cout << "The subject attributes:" << std::endl;
            for(const auto& attribute: attributes) {
                std::cout << attribute << std::endl;
            }

//            if (!attributes.empty()) {
//                auto attribute = attributes.front();
//                oidcClientTDF->addDataAttribute(attribute, "");
//            }
            // Test tdf with user creds
            testTDFOperations(oidcClientTDF.get());
#endif

#if LOCAL_EAS_KAS_SETUP
            auto tdfClient = std::make_unique<TDFClient>(easUrl, user);
            testTDFOperations(tdfClient.get());
#endif
        }
        catch (const Exception &exception) {
            BOOST_FAIL(exception.what());
        } catch (const std::exception &exception) {
            BOOST_FAIL(exception.what());
            std::cout << exception.what() << std::endl;
        } catch (...) {
            BOOST_FAIL("Unknown exception...");
            std::cout << "Unknown..." << std::endl;
        }
    }

    BOOST_AUTO_TEST_CASE(test_tdf_xml_kas_eas_local) {
        try {
#if TEST_OIDC

            OIDCCredentials clientCreds;
            clientCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                         ORGANIZATION_NAME, OIDC_ENDPOINT);
            auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds, KAS_URL);
            oidcClientTDF->setXMLFormat();

            auto attributes = oidcClientTDF->getSubjectAttributes();
            std::cout << "The subject attributes:" << std::endl;
            for(const auto& attribute: attributes) {
                std::cout << attribute << std::endl;
            }

            if (!attributes.empty()) {
                auto attribute = attributes.front();
                oidcClientTDF->addDataAttribute(attribute, "");
            }

            // Test tdf with user creds
            testTDFOperations(oidcClientTDF.get());
#endif

        }
        catch (const Exception &exception) {
            BOOST_FAIL(exception.what());
        } catch (const std::exception &exception) {
            BOOST_FAIL(exception.what());
            std::cout << exception.what() << std::endl;
        } catch (...) {
            BOOST_FAIL("Unknown exception...");
            std::cout << "Unknown..." << std::endl;
        }
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_boost_endian) {
        test24BitBigEndian(16777215); // Max 3 byte unsigned value.
        test24BitBigEndian(0);
        test24BitBigEndian(8 * 1024 * 1024);
        test24BitBigEndian(2 * 1024 * 1024);
        test24BitBigEndian(34567);
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_client_simple) {

#if TEST_OIDC

        OIDCCredentials clientCreds;
        clientCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                     ORGANIZATION_NAME, OIDC_ENDPOINT);

        auto encryptNanoTDFClientOIDC = std::make_unique<NanoTDFClient>(clientCreds, KAS_URL);
        //client1->shareWithUsers({user, user2});
        auto decryptNanoTDFClientOIDC = std::make_unique<NanoTDFClient>(clientCreds, KAS_URL);

        auto attributes = encryptNanoTDFClientOIDC->getSubjectAttributes();
        std::cout << "The subject attributes:" << std::endl;
        for(const auto& attribute: attributes) {
            std::cout << attribute << std::endl;
        }

        if (!attributes.empty()) {
            auto attribute = attributes.front();
            encryptNanoTDFClientOIDC->addDataAttribute(attribute, "");
        }

        testNanoTDFOperations(encryptNanoTDFClientOIDC.get(), decryptNanoTDFClientOIDC.get());
#endif


#if LOCAL_EAS_KAS_SETUP
        auto encryptNanoTDFClient = std::make_unique<NanoTDFClient>(easUrl, user);
        encryptNanoTDFClient->shareWithUsers({user, user2});

        auto decryptNanoTDFClient = std::make_unique<NanoTDFClient>(easUrl, user2);
        testNanoTDFOperations(encryptNanoTDFClient.get(), decryptNanoTDFClient.get());

#endif
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_client_nemo_command_dispatch_use_case) {

#if LOCAL_EAS_KAS_SETUP

        /// C&C key-pair
        auto curveName = ECCMode::GetEllipticCurveName(EllipticCurve::SECP256R1);
        auto commandAndControlECKeyPair = ECKeyPair::Generate(curveName);

//        auto commandAndControlPrivateKey = commandAndControlECKeyPair->PrivateKeyInPEMFormat();
//        auto commandAndControlPublicKey = commandAndControlECKeyPair->PublicKeyInPEMFormat();
//
//        /// Raspberry Pi's(Device-777) key-pair
//        auto device777ECKeyPair = ECKeyPair::Generate(curveName);
//        auto device777PrivateKey = device777ECKeyPair->PrivateKeyInPEMFormat();
//        auto device777PublicKey = device777ECKeyPair->PublicKeyInPEMFormat();


        // Command and Control
        const auto commandAndControlPublicKey = R"(-----BEGIN CERTIFICATE-----
MIIB4jCBywIUDuAfN1Hc6NYLfr4RzjVkcw8lJygwDQYJKoZIhvcNAQELBQAwEDEO
MAwGA1UEAwwFY2EuLWEwHhcNMjAwODI0MTUwNTM4WhcNMjAwODI1MTUwNTM4WjAX
MRUwEwYDVQQDDAxDaGFybGllXzEyMzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATlAvZOUKJhH1sGB0o/H/RP8vn1cAQlLn8O46fg93gruKxlS7sXhG5FOr7xL20O
S7B+sU48QXGjHuCWjtryxDR/MA0GCSqGSIb3DQEBCwUAA4IBAQBj5qLyIukvX9jE
dZdnrA6wTBfJ14jztNTn4fPPHsUTKYjibzSWe2cZKbpHs2545HgIqrlM/sHfIgd2
GIWZdK7aHKQTHz8Av1tD+uUT3XtMEGejeJEFM6oL32ATHslwlL/dd4RJ36Yimpup
DGN37wW3mKSyI5Aufa600IFetAT+n7kpTq4YSFQEpfPsQ6pc4CmSUhAcHtPZB/yQ
q26BzXDHq6XnGe0FcVWFRfKRPA+izLdWauGd2Em5AKbdlZ5mM5fo/hm10kaeadaH
hzDqjzkqZJsalauVnweVlcKTYmK56TCl5+Re6l1kyZxSR9H5gXYIUiKo1k9YcZA5
RBwIFZN8
-----END CERTIFICATE-----
)"s;
        const auto commandAndControlPrivateKey  = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgclkytr7jA1fYe65o
GHv5uxpO0htaRbXg4bZC4wIizDKhRANCAATlAvZOUKJhH1sGB0o/H/RP8vn1cAQl
Ln8O46fg93gruKxlS7sXhG5FOr7xL20OS7B+sU48QXGjHuCWjtryxDR/
-----END PRIVATE KEY-----
)"s;

        /// Raspberry Pi's(Device-777) key-pair
        auto device777ECKeyPair = ECKeyPair::Generate(curveName);
        const auto device777PublicKey  = R"(-----BEGIN CERTIFICATE-----
MIIB4jCBywIUFufoKE3C5A1jo4fGfwrZ0A6xteYwDQYJKoZIhvcNAQELBQAwEDEO
MAwGA1UEAwwFY2EuLWEwHhcNMjAwODI0MTUwOTI1WhcNMjAwODI1MTUwOTI1WjAX
MRUwEwYDVQQDDAxDaGFybGllXzEyMzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAR4bFFjf6wAOGquwxobnWdEUw4ZctzLaviKeWq6GU4X5AJ/ZHmZmPqZjdpwsQxU
iaVAFMrWjj4v3iwNeJD2fhjIMA0GCSqGSIb3DQEBCwUAA4IBAQCpVqpwpjHkGWpz
SNQ1oTXOI6V0t62QVu1QM3x5oFiUfIzft6tPwaNE1oD1FT9yO1v8jBMmf+52SwVu
yqkH10hRuuwXR4Ws2I/j9RMXwTgiii7C47mBLlLwmzL3yu53KXllvWrUwuO4joux
pWNJRbjseUkH/X/qcHDZdiYuzcbuYb3ekSP8Lb8ol+qgD4SsXx3XMCfEPkujr/c8
oCGyfoXS6mpET+Zrp7hgwSkJuTLHT9AIpGhZYedSj6hHgjKcZpWak66a7lHPgz9g
ENna9CRO+dtFmSZBKv25JkzQaVVsApgMVy0zXsx3nmLN09lKPi3SzzGs3DpW2s9q
7JIebpJQ
-----END CERTIFICATE-----
)"s;
        const auto device777PrivateKey = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrSjDJBMPzKZo4OrP
+Yq+Yhj0gJplc786XaDWTzxfkVKhRANCAAR4bFFjf6wAOGquwxobnWdEUw4ZctzL
aviKeWq6GU4X5AJ/ZHmZmPqZjdpwsQxUiaVAFMrWjj4v3iwNeJD2fhjI
-----END PRIVATE KEY-----
)"s;


        ///-------------------------------------------- COMMAND AND CONTROL -------------------------------------
        ///
        /// NOTE: C&C knows it's key-pair and all the devices public-keys
        ///
        std::string command{"Collect Data"};
        std::string commandFile{"command.txt"};
        std::string ntdfFile{"command.txt.ndtf"};
        std::string commandFileResult{"command-result.txt"};
        std::string commandAsNanoTDF;
        {
            /// Create SDK instance on C&C
//            NanoTDFClient commandAndControlNanoTDFClient{easUrl, "CN=Charlie_1234",
//                                                         "data/client.key", "data/client.crt",
//                                                         "data/ca.crt"};

            NanoTDFClient commandAndControlNanoTDFClient{easUrl, user};

            // NOTE: Send the decrypter public key so the device can decrypt in offline mode.
            commandAndControlNanoTDFClient.setDecrypterPublicKey(device777PublicKey);

            commandAndControlNanoTDFClient.setSignerPrivateKey(commandAndControlPrivateKey, EllipticCurve::SECP256R1);
            commandAsNanoTDF = commandAndControlNanoTDFClient.encryptString(command);

            std::ofstream outFileStream{commandFile, std::ios_base::out | std::ios_base::binary};
            if (!outFileStream) {
                BOOST_FAIL("Failed to open file for writing.");
            }

            outFileStream << command;
            outFileStream.close();

            commandAndControlNanoTDFClient.encryptFile(commandFile, ntdfFile);
        }

        /// ----- Send a command as nano tdf via different medium ----

        ///-------------------------------------------- Raspberry Pi(Decrypt in offline mode) -------------------------------------
        ///
        /// NOTE: Raspberry Pi knows it's key-pair and C&C public key
        ///
        {
            /// Create SDK instance on Pi
            NanoTDFClient deviceNanoTDFClient{};
            deviceNanoTDFClient.setEntityPrivateKey(device777PrivateKey, EllipticCurve::SECP256R1);

            deviceNanoTDFClient.validateSignature(commandAndControlPublicKey);
            auto commandAfterDecrypt = deviceNanoTDFClient.decryptString(commandAsNanoTDF);
            BOOST_TEST(command == commandAfterDecrypt);

            deviceNanoTDFClient.decryptFile(ntdfFile, commandFileResult);
        }

#endif
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_client_camera_use_case) {

#if LOCAL_EAS_KAS_SETUP

        // NOTE: Assume the curve as secp256r1
        auto curveType = EllipticCurve::SECP256R1;
        auto curveName = ECCMode::GetEllipticCurveName(curveType);

        std::array<std::string, 4u> cameraData = {"Installed success!!", "Object-1", "Object-2", "Object-3"};

        ///-------------------------------------------- Camera -------------------------------------
        std::string eoAsString;
        std::string entityPrivateKey;
        std::vector<std::string> dataStore;

        { // Camera is getting installed.

            NanoTDFClient initPhaseClient{easUrl, user2};

            // TODO: Add data attributes.
            //collectInfoClient.addDataAttribute("");

            auto tdf = initPhaseClient.encryptString(cameraData[0]);

            dataStore.emplace_back(tdf);

            // save eo and key so the camera can encrypt data when thers is no connectivity
            eoAsString = initPhaseClient.getEntityObject().toJsonString();
            auto pairOfKeyAndCurve = initPhaseClient.getEntityPrivateKeyAndCurve();
            entityPrivateKey = pairOfKeyAndCurve.first;
        }

        { // Camera installed and there is no network connectivity.

            NanoTDFClient collectInfoClient{easUrl, user2};
            collectInfoClient.setEntityPrivateKey(entityPrivateKey, curveType);
            collectInfoClient.setEntityObjectAsJsonString(eoAsString);

            // TODO: Add data attributes.
            //collectInfoClient.addDataAttribute("");

            auto tdf = collectInfoClient.encryptString(cameraData[1]);
            dataStore.emplace_back(tdf);

            tdf = collectInfoClient.encryptString(cameraData[2]);
            dataStore.emplace_back(tdf);

            tdf = collectInfoClient.encryptString(cameraData[3]);
            dataStore.emplace_back(tdf);
        }

        { // On server-side have the data from data store.

            NanoTDFClient decryptClient{easUrl, user2};
            for (size_t index = 0; index < dataStore.size(); ++index) {
                auto data = decryptClient.decryptString(dataStore[index]);
                BOOST_TEST(data == cameraData[index]);
            }
        }

#endif
    }


BOOST_AUTO_TEST_SUITE_END()

