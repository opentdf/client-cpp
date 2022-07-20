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
#include "test_utils.h"
#include "tdf_exception.h"
#include "file_io_provider.h"
#include "tdf_archive_reader.h"

#include <boost/test/included/unit_test.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <istream>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#if RUN_BACKEND_TESTS
    #define TEST_OIDC 1
#else
    #define TEST_OIDC 0
#endif

#define LOCAL_EAS_KAS_SETUP 0
constexpr auto user = "user1";
constexpr auto user2 = "user2";
constexpr auto easUrl = "http://localhost:8000/";
constexpr auto OIDC_ENDPOINT = "http://localhost:65432/";
constexpr auto KAS_URL = "http://localhost:65432/api/kas";
constexpr auto CLIENT_ID = "tdf-client";
constexpr auto CLIENT_SECRET = "123-456";
constexpr auto ORGANIZATION_NAME = "tdf";


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

void testTDFOperations(TDFClient* client, bool testMetaDataAPI = false) {
    std::string currentDir = TestUtils::getCurrentWorkingDir();
    const std::string metaData = R"({"displayName" : "opentdf c++ sdk"})";

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
    client->setEncryptedMetadata(metaData);

    TDFStorageType encryptFileType;
    encryptFileType.setTDFStorageFileType(inPathEncrypt);
    client->encryptFile(encryptFileType, outPathEncrypt);

    if (testMetaDataAPI) {
        TDFStorageType fileType;
        fileType.setTDFStorageFileType(outPathEncrypt);
        auto metaDataFromTDF = client->getEncryptedMetadata(fileType);
        BOOST_TEST(metaData == metaDataFromTDF);
    }

    TDFStorageType decryptFileType;
    decryptFileType.setTDFStorageFileType(inPathDecrypt);
    client->decryptFile(decryptFileType, outPathDecrypt);

    BOOST_TEST_MESSAGE("TDF basic test passed.");
    std::array<std::uint32_t, 10u> bufferSizes{1, 10, 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024,
                                               8 * 1024 * 1024, (16 * 1024 * 1024 - 35), 100, 1000, 8000 };
    for (const auto& size : bufferSizes) {

        std::string plainText = TestUtils::randomString(size);

        TDFStorageType encryptStringType;
        encryptStringType.setTDFStorageStringType(plainText);
        auto encryptedText = client->encryptData(encryptStringType);

        TDFStorageType decryptBufferType;
        decryptBufferType.setTDFStorageBufferType(encryptedText);
        auto plainTextAfterDecrypt = client->decryptData(decryptBufferType);
        std::string plainTextAfterTDFOp(plainTextAfterDecrypt.begin(), plainTextAfterDecrypt.end());

        BOOST_TEST(plainText == plainTextAfterTDFOp);
    }
}

void testNanoTDFOperations(TDFClientBase* client1, NanoTDFClient* client2) {

    // IV - 3 bytes, Max Auth tag - 32 bytes, so total of 35 bytes overhead for the payload 
    std::array<std::uint32_t, 10u> fileSizeArray{0, 1, 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024,
                                                 8 * 1024 * 1024, (16 * 1024 * 1024 - 35), 100, 1000, 2000 };

    { // File tests with signature.

        for (const auto& size : fileSizeArray) {
            std::string plainText = TestUtils::randomString(size);
            { // Write file
                std::ofstream f("nano_tdf_text.txt");
                f.write(plainText.data(), plainText.size());
            }

            TDFStorageType encryptFileType;
            encryptFileType.setTDFStorageFileType("nano_tdf_text.txt");
            client1->encryptFile(encryptFileType, "nano_tdf_text.txt.ntdf");

            TDFStorageType decryptFileType;
            decryptFileType.setTDFStorageFileType("nano_tdf_text.txt.ntdf");
            client2->decryptFile(decryptFileType, "nano_tdf_text_out.txt");

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

            std::string plainText = TestUtils::randomString(size);

            TDFStorageType bufferType;
            bufferType.setTDFStorageStringType(plainText);

            auto encryptedText = client1->encryptData(bufferType);

            TDFStorageType decryptBufferType;
            decryptBufferType.setTDFStorageBufferType(encryptedText);

            auto plainTextAfterDecrypt = client2->decryptData(decryptBufferType);
            std::string plaintTextStr(plainTextAfterDecrypt.begin(), plainTextAfterDecrypt.end());
            BOOST_TEST(plainText == plaintTextStr);
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

        std::string currentDir = TestUtils::getCurrentWorkingDir();
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
        std::string currentDir = TestUtils::getCurrentWorkingDir();
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

    BOOST_AUTO_TEST_CASE(test_is_tdf) {

        std::string currentDir = TestUtils::getCurrentWorkingDir();
#ifdef _WINDOWS
        std::string validZipTDFFilePath {currentDir };
        validZipTDFFilePath.append("\\data\\valid_zip_tdf.tdf");

        std::string validXmlTDFFilePath {currentDir };
        validXmlTDFFilePath.append("\\data\\valid_xml_tdf.tdf");

        std::string validHtmlTDFFilePath {currentDir };
        validHtmlTDFFilePath.append("\\data\\valid_html_tdf.tdf");

        std::string invalidZipTDFFilePath {currentDir };
        invalidZipTDFFilePath.append("\\data\\invalid_zip_tdf.tdf");

        std::string invalidXmlTDFFilePath {currentDir };
        invalidXmlTDFFilePath.append("\\data\\invalid_xml_tdf.tdf");

        std::string invalidHtmlTDFFilePath {currentDir };
        invalidHtmlTDFFilePath.append("\\data\\invalid_html_tdf.tdf");
#else
        std::string validZipTDFFilePath {currentDir };
        validZipTDFFilePath.append("/data/valid_zip_tdf.tdf");

        std::string validXmlTDFFilePath {currentDir };
        validXmlTDFFilePath.append("/data/valid_xml_tdf.tdf");

        std::string validHtmlTDFFilePath {currentDir };
        validHtmlTDFFilePath.append("/data/valid_html_tdf.tdf");

        std::string invalidZipTDFFilePath {currentDir };
        invalidZipTDFFilePath.append("/data/invalid_zip_tdf.tdf");

        std::string invalidXmlTDFFilePath {currentDir };
        invalidXmlTDFFilePath.append("/data/invalid_xml_tdf.tdf");

        std::string invalidHtmlTDFFilePath {currentDir };
        invalidHtmlTDFFilePath.append("/data/invalid_html_tdf.tdf");
#endif
        BOOST_TEST(TDFClient::isFileTDF(validZipTDFFilePath) == true);
        BOOST_TEST(TDFClient::isFileTDF(invalidZipTDFFilePath) == false);
        BOOST_TEST(TDFClient::isStringTDF(invalidZipTDFFilePath) == false);

        BOOST_TEST(TDFClient::isFileTDF(validXmlTDFFilePath) == true);
        BOOST_TEST(TDFClient::isFileTDF(invalidXmlTDFFilePath) == false);
        BOOST_TEST(TDFClient::isStringTDF(invalidXmlTDFFilePath) == false);

        BOOST_TEST(TDFClient::isFileTDF(validHtmlTDFFilePath) == true);
        BOOST_TEST(TDFClient::isFileTDF(invalidHtmlTDFFilePath) == false);
        BOOST_TEST(TDFClient::isStringTDF(invalidHtmlTDFFilePath) == false);

        BOOST_TEST(TDFClient::isStringTDF(TestUtils::getFileString(validZipTDFFilePath)) == true);
        BOOST_TEST(TDFClient::isStringTDF(TestUtils::getFileString(invalidZipTDFFilePath)) == false);

        BOOST_TEST(TDFClient::isStringTDF(TestUtils::getFileString(validXmlTDFFilePath)) == true);
        BOOST_TEST(TDFClient::isStringTDF(TestUtils::getFileString(invalidXmlTDFFilePath)) == false);

        BOOST_TEST(TDFClient::isStringTDF(TestUtils::getFileString(validHtmlTDFFilePath)) == true);
        BOOST_TEST(TDFClient::isStringTDF(TestUtils::getFileString(invalidHtmlTDFFilePath)) == false);
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
            testTDFOperations(oidcClientTDF.get(), true);
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

    BOOST_AUTO_TEST_CASE(test_tdf_partial_decrypt) {
        try {

#if TEST_OIDC

            {
                // Create a 5GB file
                std::string fileName{"sample_5gb_for_partial_decrypt.txt"};
                std::string tdfFileName{"sample_5gb_for_partial_decrypt.txt.tdf"};
                size_t filesize = 0;
                auto segmentSize = 1024*1024;
                {
                    std::ofstream outStream{fileName.c_str(), std::ios_base::out | std::ios_base::binary};
                    if (!outStream) {
                        BOOST_FAIL("Failed to open file for writing sample data for partial decrypt.");
                    }

                    // size = 8mb * 512
                    auto counter = 512;
                    std::array<char, 8u> sampleData = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
                    filesize = sampleData.size() * segmentSize * counter;
                    for(auto index = 0; index < counter ; index++) {
                        std::vector<char> segment(segmentSize);
                        for (const auto& byte: sampleData) {
                            std::fill(segment.begin(), segment.end(), byte);
                            outStream.write(segment.data(), segmentSize);
                        }
                    }
                }

                OIDCCredentials clientCreds;
                clientCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                             ORGANIZATION_NAME, OIDC_ENDPOINT);
                auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds, KAS_URL);

                TDFStorageType fileType;
                fileType.setTDFStorageFileType(fileName);
                oidcClientTDF->encryptFile(fileType, tdfFileName);

                TDFStorageType tdfStorageFileType;
                tdfStorageFileType.setTDFStorageFileType(tdfFileName);

                {
                    auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 0, 10);
                    std::string strPlainData(plainData.begin(), plainData.end());
                    BOOST_TEST(strPlainData ==  "aaaaaaaaaa");
                }

                // 1mb + 1 byte from middle
                {
                    auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 241* segmentSize, segmentSize+1);
                    std::string expectedData(segmentSize, 'b');
                    expectedData.append("c");

                    std::string strPlainData(plainData.begin(), plainData.end());
                    if (expectedData != strPlainData) {
                        BOOST_FAIL("decryptFilePartial test failed");
                    }
                }

                // last 10 bytes
                auto last10BytesIndex = filesize - 10;
                {
                    auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, last10BytesIndex, 10);
                    std::string strPlainData(plainData.begin(), plainData.end());
                    if (strPlainData != "hhhhhhhhhh") {
                        BOOST_FAIL("decryptFilePartial test failed");
                    }
                }

                // Expect exception the request length is not valid
                auto longLength = 6*segmentSize;
                BOOST_CHECK_THROW(oidcClientTDF->decryptDataPartial(tdfStorageFileType, last10BytesIndex, 100),
                                  virtru::Exception);
            }

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

    BOOST_AUTO_TEST_CASE(test_tdf_with_io_provider) {
#if TEST_OIDC
        OIDCCredentials clientCreds;
        clientCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                     ORGANIZATION_NAME, OIDC_ENDPOINT);
        auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds, KAS_URL);

        const size_t sizeOfData = 25 * 1024 * 1024; // 25 mb

        static std::vector<gsl::byte> plainData(sizeOfData);
        std::fill(plainData.begin(), plainData.end(), gsl::byte(0xFF));

        static std::vector<gsl::byte> encryptedBuffer;

        { // Encrypt with I/O Providers
            struct CustomInputProvider: IInputProvider {
                void readBytes(size_t index, size_t length, WriteableBytes &bytes) override {
                    std::memcpy(bytes.data(), plainData.data() + index, length);
                }

                size_t getSize() override { return sizeOfData; }
            };

            struct CustomOutputProvider: IOutputProvider {
                void writeBytes(Bytes bytes) override {
                    encryptedBuffer.insert(encryptedBuffer.end(), bytes.begin(), bytes.end());
                }
                void flush() override { /* Do nothing */ }
            };

            CustomInputProvider inputProvider{};
            CustomOutputProvider outputProvider{};
            oidcClientTDF->encryptWithIOProviders(inputProvider, outputProvider);

//            std::string writeData;
//            writeData.append(reinterpret_cast<char *>(encryptedBuffer.data()), encryptedBuffer.size());
//            std::cout << "The TDF Data is:" <<  writeData << std::endl;
        }

        static std::vector<gsl::byte> decryptData;
        { // Decrypt with I/0 Providers

            struct CustomInputProvider: IInputProvider {
                void readBytes(size_t index, size_t length, WriteableBytes &bytes) override {
                    std::memcpy(bytes.data(), encryptedBuffer.data() + index, length);
                }

                size_t getSize() override { return encryptedBuffer.size(); }
            };

            struct CustomOutputProvider: IOutputProvider {
                void writeBytes(Bytes bytes) override {
                    decryptData.insert(decryptData.end(), bytes.begin(), bytes.end());
                }
                void flush() override { /* Do nothing */ }
            };

            CustomInputProvider inputProvider{};
            CustomOutputProvider outputProvider{};
            oidcClientTDF->decryptWithIOProviders(inputProvider, outputProvider);
        }

        BOOST_TEST(plainData == decryptData);
#endif
    }


BOOST_AUTO_TEST_SUITE_END()

