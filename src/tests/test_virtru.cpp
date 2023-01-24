//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/28.
//  Copyright 2019 Virtru Corporation
//

//E2E tests make network calls, and require additional setup - don't run them
//as part of normal unit test flow, they're not unit tests.

#define BOOST_TEST_MODULE test_e2e_module

#include "tdfbuilder.h"
#include "tdf.h"
#include "network/http_client_service.h"
#include "tdf_exception.h"
#include "tdf_logging_interface.h"
#include "crypto/rsa_key_pair.h"
#include "entity_object.h"
#include "sdk_constants.h"
#include "network/http_service_provider.h"
#include "network_interface.h"
#include "logger.h"
#include "policy_object.h"
#include "crypto/bytes.h"
#include "io_provider.h"
#include "rca_io_provider.h"
#include "utils.h"

#include "nlohmann/json.hpp"
#include <memory>
#include <boost/test/included/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <stdio.h>
#include <iostream>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#define TEST_ENCRYPT_DECRYPT    1

//constexpr auto tokenId = "23a6346d-8586-4033-99f7-49b5de8d274d@tokens.virtru.com";
//constexpr auto tokenSecret = "pAVzOi1XDOIce093I4iZJuRr90D4N9TB0E/NP5K+rOg=";
//constexpr auto entityObjectURLForHmac = "https://accounts-develop01.develop.virtru.com/api/entityobject?userId=sreddy@trusteddataformat.org";
//#ifdef KAS_LOCALHOST
//constexpr auto kasPublicKeyUrl = "http://localhost:4300/kas_public_key";
//constexpr auto kasHost = "localhost";
//constexpr auto kasUrl = "http://localhost:4300";
//#elif VBUILD_TESTENV_STAGING
//constexpr auto kasPublicKeyUrl = "https://api.staging.virtru.com/kas/kas_public_key";
//constexpr auto kasHost = "api.staging.virtru.com";
//constexpr auto kasUrl = "https://api.staging.virtru.com/kas";
//constexpr auto easUrl = "https://api.staging.virtru.com/accounts";
//constexpr auto easHost = "api.staging.virtru.com";
//#else
//constexpr auto kasPublicKeyUrl = "https://api-develop01.develop.virtru.com/kas/kas_public_key";
//constexpr auto kasHost = "api-develop01.develop.virtru.com";
//constexpr auto kasUrl = "https://api-develop01.develop.virtru.com/kas";
//constexpr auto easUrl = "https://api-develop01.develop.virtru.com/accounts";
//constexpr auto easHost = "api-develop01.develop.virtru.com";
//#endif

//constexpr auto kasPublicKeyUrl = "https://api.staging.virtru.com/kas/kas_public_key";
//constexpr auto kasHost = "api.staging.virtru.com";
//constexpr auto kasUrl = "https://api.staging.virtru.com/kas";
//constexpr auto easUrl = "https://api.staging.virtru.com/accounts";
//constexpr auto easHost = "api.staging.virtru.com";

//constexpr auto kasPublicKeyUrl = "https://api.virtru.com/kas/kas_public_key";
//constexpr auto kasHost = "api.virtru.com";
//constexpr auto kasUrl = "https://api.virtru.com/kas";
//constexpr auto easUrl = "https://api.virtru.com/accounts";
//constexpr auto easHost = "api.virtru.com";

constexpr auto kasPublicKeyUrl = "https://api-develop01.develop.virtru.com/kas/kas_public_key";
constexpr auto kasHost = "api-develop01.develop.virtru.com";
constexpr auto kasUrl = "https://api-develop01.develop.virtru.com/kas";
constexpr auto easUrl = "https://api.develop.virtru.com/accounts";
constexpr auto easHost = "api-develop01.develop.virtru.com";

constexpr auto AcceptHeaderKey = "Accept";
constexpr auto AcceptHeaderValue = "application/json; charset=utf-8";
constexpr auto UserAgentHeaderKey = "User-Agent";
constexpr auto UserAgentValuePostFix = "Virtru TDF C++ SDK v0.0";
constexpr auto VirtruClientKey = "Virtru TDF C++ SDK v0.0";

using namespace virtru::network;
using namespace virtru::crypto;
using namespace virtru;
using namespace boost::unit_test;

std::string user() {
    auto username = getenv("VIRTRU_USER_USERNAME");
    if (username){
        return username;
    }
    return {"tdf3-user@virtrucanary.com"};
}

std::string appId() {
    auto appId = getenv("VIRTRU_USER_APPID");
    if (appId) {
        return appId;
    }
    return {"dc7f7d6e-d5f1-449f-8641-6a572ab8a1dd"};
}

std::string getCurrentWorkingDir() {
    char buff[FILENAME_MAX];
    GetCurrentDir( buff, FILENAME_MAX );
    std::string current_working_dir(buff);
    return current_working_dir;
}

// EntityObject getEntityObject(const std::string& publicKey);

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

std::string getKasPublicKey() {

    std::string publicKey;
    // Set user agent (ex: <Mac OS/Linux>:Virtru TDF C++ SDK v0.1)
    std::ostringstream sdkUserAgent;
    sdkUserAgent << BOOST_PLATFORM << ":" << UserAgentValuePostFix;

    auto service = Service::Create(kasPublicKeyUrl);
    service->AddHeader(kHostKey, kasHost);
    service->AddHeader(UserAgentHeaderKey, sdkUserAgent.str());
    service->AddHeader(AcceptHeaderKey, AcceptHeaderValue);

    IOContext ioContext;
    service->ExecuteGet(ioContext,  [&publicKey](ErrorCode errorCode, HttpResponse&& response) {
        if (errorCode) { // something wrong.

            std::ostringstream os {"Error code: "};
            os << errorCode.value() << " " << errorCode.message();
        }

        publicKey.append(response.body());
        // TODO: Enable if verbose logging is required.
        //std::cout << "kas_public_key Response: " << response.body().data() << std::endl;
    });

    // Run the context - It's blocking call until i/o operation is done.
    ioContext.run();

    publicKey.erase(0, 1);
    publicKey.erase(publicKey.size() - 2);

    publicKey = ReplaceAll(publicKey, "\\n", "\n");

    return publicKey;
}

EntityObject getEntityObject(const std::string& publicKey) {

    std::ostringstream authHeaderValue;
    authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
    //std::cout << "Auth-header:" << authHeaderValue.str() << std::endl;

    static constexpr auto kEntityobjectURL = "/api/entityobject";

    std::string eoFullUrl = easUrl;
    eoFullUrl += kEntityobjectURL;

    auto service = Service::Create(eoFullUrl);
    service->AddHeader(kHostKey, easHost);
    service->AddHeader(AcceptHeaderKey, AcceptHeaderValue);
    service->AddHeader(kAuthorizationKey, authHeaderValue.str());
    service->AddHeader(kContentTypeKey, kContentTypeJsonValue);
    service->AddHeader(kVirtruClientKey, VirtruClientKey);

    nlohmann::json publicKeyBody;
    publicKeyBody["publicKey"] = publicKey;
    std::string entityObjectJson;

    //std::string body = to_string(publicKeyBody);

    // TODO: Enable if verbose logging is required.
    //std::cout << "body: " << body << std::endl;

    IOContext ioContext;
    service->ExecutePost(to_string(publicKeyBody), ioContext,
                         [&entityObjectJson](ErrorCode errorCode, HttpResponse&& response) {
                             // TODO: Ignore stream truncated error. Looks like the server is not shuting downn gracefully.
                             // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
                             if (errorCode && errorCode.value() != 1) { // something is wrong

                                 std::ostringstream os {"Error code: "};
                                 os << errorCode.value() << " " << errorCode.message();
                                 std::cerr << "Error code: " << os.str() << std::endl;
                             }
                             else {
                                 // TODO: Enable if verbose logging is required.
                                 //std::cout << "api/entityobject Response: " << response.body().data() << std::endl;
                                 entityObjectJson = response.body().data();
                             }
                         });

    // Run the context - It's blocking call until i/o operation is done.
    ioContext.run();

    // TODO: Enable if verbose logging is required.
    //std::cout << "api/entityobject Response: " << entityObjectJson << std::endl;
    auto entityObject = EntityObject::createEntityObjectFromJson(entityObjectJson);
    return entityObject;
}

std::unique_ptr<TDFBuilder> createTDFBuilder(LogLevel logLevel, KeyAccessType keyAccessType, Protocol protocol) {

    auto keyPairOf2048 = crypto::RsaKeyPair::Generate(2048);
    std::string kasPublicKey = keyPairOf2048->PublicKeyInPEMFormat();
    std::string publicKey = keyPairOf2048->PublicKeyInPEMFormat();
    EntityObject entityObject{};

    kasPublicKey = getKasPublicKey();
    entityObject = getEntityObject(publicKey);

    std::string mimeType{"text/plain"};

    std::unordered_map<std::string, std::string> metaData;
    metaData.insert({"displayName", "tdf-cpp-unit-tests"});
    metaData.insert({"fileProvider", "tdf-cpp-sdk"});

    auto tdfbuilderPtr = std::make_unique<TDFBuilder>(user());

    tdfbuilderPtr->setKasUrl(kasUrl)
            .setEasUrl(easUrl)
            .enableConsoleLogging(logLevel)
            .setDefaultSegmentSize(2 * 1024 * 1024)
            .setKasPublicKey(kasPublicKey)
            .setPrivateKey(keyPairOf2048->PrivateKeyInPEMFormat())
            .setPublicKey(publicKey)
            .setEntityObject(entityObject)
            .setProtocol(protocol)
            .setEncryptionObject(KeyType::split, CipherType::Aes256GCM)
            .setIntegrityAlgorithm(IntegrityAlgorithm::HS256, IntegrityAlgorithm::GMAC)
            .setPayloadMimeType(mimeType)
            .setMetaData(metaData);

    if (keyAccessType == KeyAccessType::Remote) {
        tdfbuilderPtr->setKeyAccessType(KeyAccessType::Remote);
    } else {
        tdfbuilderPtr->setKeyAccessType(KeyAccessType::Wrapped);
    }

    if (protocol == Protocol::Html) {
        std::string secureReaderUrl{"https://secure-develop01.develop.virtru.com/start?htmlProtocol=1"};

        std::string currentDir = getCurrentWorkingDir();
        std::string htmlTemplateFilepath {currentDir };

#ifdef _WINDOWS
        htmlTemplateFilepath.append("\\data\\tdf-html-template.html");
#else
        htmlTemplateFilepath.append("/data/tdf-html-template.html");
#endif

        // Copy the html template file data into the buffer.
        std::string htmlTemplateData;
        std::ifstream ifs(htmlTemplateFilepath.data(), std::ios::binary | std::ios::ate);
        if (!ifs) {
            std::string errorMsg{"Failed to open file for reading - "};
            errorMsg.append(htmlTemplateData);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        std::ifstream::pos_type fileSize = ifs.tellg();
        htmlTemplateData.reserve(fileSize);
        ifs.seekg(0, std::ios::beg);
        htmlTemplateData.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());

        tdfbuilderPtr->setHtmlTemplateData(std::move(htmlTemplateData));
        tdfbuilderPtr->setSecureReaderURL(secureReaderUrl);
    }

    return tdfbuilderPtr;
}

void testSourceAndSinkInterface(TDF* tdf) {
    ByteArray<5> buffer;
    static std::string plainText{ "Virtru offers data protection solutions for the most commonly used"
                                  " tools and applications across all industries" };
    static std::vector<gsl::byte> encryptedBuffer;
    encryptedBuffer.clear();

    static std::vector<gsl::byte> plainTextBuffer(plainText.size());
    std::memcpy(plainTextBuffer.data(), plainText.data(), plainText.size());

    { // Encrypt with I/O Providers
        struct CustomInputProvider: IInputProvider {
            void readBytes(size_t index, size_t length, WriteableBytes &bytes) override {
                std::memcpy(bytes.data(), plainText.data() + index, length);
            }

            size_t getSize() override { return plainText.size(); }
        };

        struct CustomOutputProvider: IOutputProvider {
            void writeBytes(Bytes bytes) override {
                encryptedBuffer.insert(encryptedBuffer.end(), bytes.begin(), bytes.end());
            }
            void flush() override { /* Do nothing */ }
        };

        CustomInputProvider inputProvider{};
        CustomOutputProvider outputProvider{};
        tdf->encryptIOProvider(inputProvider, outputProvider);
    }

    static std::vector<gsl::byte> decryptData;
    decryptData.clear();
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
        tdf->decryptIOProvider(inputProvider, outputProvider);
    }

    BOOST_TEST(plainTextBuffer == decryptData);
}

BOOST_AUTO_TEST_SUITE(test_e2e_tdf_builder_suite)


    using namespace virtru;


    BOOST_AUTO_TEST_CASE(test_tdf_builder_basic) {

        std::ostringstream authHeaderValue;
        authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
        HttpHeaders headers = { {kAcceptKey, kAcceptKeyValue},
                                {kAuthorizationKey, authHeaderValue.str()}};

        constexpr auto entityObjectJsonStr = "{\n"
                                             "    \"aliases\": [\"sreddy@trusteddataformat.org\", \"sreddy@trusteddataformat.net\"], \n"
                                             "    \"attributes\": [\n"
                                             "        {\n"
                                             "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci91bmlxdWUtaWRlbnRpZmllci92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.qg8BYLJ6ZKu6e641_NLfjlghDwWexEr_YUCadUyPX-B1tonWIJUjGddhx2cz5H8Ldxpj0AurilCz2xAIcRItwm9-0M3RlNUAZ7l5wYahRnSWijwV4lL7Yvm_HwMYgrrVNvcUwj5cqpMREHfCDScS-lSb89zhq76dypVmkgmhZe3t9lD1fTSJKCJylc7X9AzbWzLc0fDQH702yU__ZVOVkBwTO2jJ4ovBDPB0w9LgCEZ-9pzvdUiTdYuhZ2PzQBTNHlK1xxQQCu148uuiTw8Fk_bs7efuGgUU7zfrKR2Lvgw5QLDpavL11HnXIKZihxzJbcrjBdKQCK0V7v3i7F2CkA\"\n"
                                             "        }, \n"
                                             "        {\n"
                                             "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9wcmltYXJ5LW9yZ2FuaXphdGlvbi92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.TBO2RbLIESO5h3n8Cop4DVYJNhI46nfaAIuzUuTJ73v5j0myplcj3amNyW_PPRxSauMhG5gwhkSrYHgnO-f423a7YnGW1SmfqmpEFd8s5j1yGRIytJsuaVD0B5nfrjSkS4Bu5lV8J2pYmnanZkr_Mo6oj2_IhITk0lVBTgri-PTUfGKNCFfCI3bpFH2UwbvNzJD6wniW5C9rOG7oBMSbDTOK2HJK_3mf1DifzoH0iQY2r5fyJzomtYDd2Z4BGtPnWpU6wAF3rcfOYqYDW1KA74PsPZm2kaqC7Icq1PvqFglX3QwpmvQqpEvzWSNS3nNFui5yjupkHSlXfU24CEn3EA\"\n"
                                             "        }, \n"
                                             "        {\n"
                                             "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9zdXBlci1hZG1pbi92YWx1ZS90cnVlIiwibmFtZSI6dHJ1ZSwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.pkvAvRxU3pcqTCvUCuJtCwEg8UnXkLGKUgdH7aBnHWqCix_CXt_OqJ5T-b58xlszelyvcdmvTQxyg1_aHXOKg5wDQQaA6Ur3NsbYr3oskrPI8dE8gIK326NPpqrjrpBGGXkPoJHkXwGO5GfqtoNpuFWd8Y5UDLmH1QKegsBJQAVoV6JpWGvPyP_apAL8cNPNiTHuAL2RyE17ArhziHu6Ujaq_faJaC8sghSejGjW6SpdWiSF9Kw0rV4dZWjRsRu9qbWf3grMIMqEoP-3mSlpxhpDPWTS0hRaCnSvpneQynFvhbKMA2XA0z29Z9i6JueQisrjKVJ1PiaYvZIWNzz3OA\"\n"
                                             "        }\n"
                                             "    ],\n"
                                             "     \n"
                                             "    \"cert\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJzcmVkZHlAdmlydHJ1ZGVwbG95LnVzIiwiYXR0cmlidXRlcyI6W3siand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5MWJtbHhkV1V0YVdSbGJuUnBabWxsY2k5MllXeDFaUzltWlRFelpqQm1ZUzB4Tm1VMUxUUTNaRFl0T0Rkall5MWhPVEkxTXpKaFl6Y3hZelFpTENKdVlXMWxJam9pWm1VeE0yWXdabUV0TVRabE5TMDBOMlEyTFRnM1kyTXRZVGt5TlRNeVlXTTNNV00wSWl3aWFXRjBJam94TlRVek5EZzFNalEzTENKbGVIQWlPakUxTlRNMU56RTJORGQ5LnFnOEJZTEo2Wkt1NmU2NDFfTkxmamxnaER3V2V4RXJfWVVDYWRVeVBYLUIxdG9uV0lKVWpHZGRoeDJjejVIOExkeHBqMEF1cmlsQ3oyeEFJY1JJdHdtOS0wTTNSbE5VQVo3bDV3WWFoUm5TV2lqd1Y0bEw3WXZtX0h3TVlncnJWTnZjVXdqNWNxcE1SRUhmQ0RTY1MtbFNiODl6aHE3NmR5cFZta2dtaFplM3Q5bEQxZlRTSktDSnlsYzdYOUF6Yld6TGMwZkRRSDcwMnlVX19aVk9Wa0J3VE8yako0b3ZCRFBCMHc5TGdDRVotOXB6dmRVaVRkWXVoWjJQelFCVE5IbEsxeHhRUUN1MTQ4dXVpVHc4RmtfYnM3ZWZ1R2dVVTd6ZnJLUjJMdmd3NVFMRHBhdkwxMUhuWElLWmloeHpKYmNyakJkS1FDSzBWN3YzaTdGMkNrQSJ9LHsiand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5d2NtbHRZWEo1TFc5eVoyRnVhWHBoZEdsdmJpOTJZV3gxWlM5bVpURXpaakJtWVMweE5tVTFMVFEzWkRZdE9EZGpZeTFoT1RJMU16SmhZemN4WXpRaUxDSnVZVzFsSWpvaVptVXhNMll3Wm1FdE1UWmxOUzAwTjJRMkxUZzNZMk10WVRreU5UTXlZV00zTVdNMElpd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5UQk8yUmJMSUVTTzVoM244Q29wNERWWUpOaEk0Nm5mYUFJdXpVdVRKNzN2NWowbXlwbGNqM2FtTnlXX1BQUnhTYXVNaEc1Z3doa1NyWUhnbk8tZjQyM2E3WW5HVzFTbWZxbXBFRmQ4czVqMXlHUkl5dEpzdWFWRDBCNW5mcmpTa1M0QnU1bFY4SjJwWW1uYW5aa3JfTW82b2oyX0loSVRrMGxWQlRncmktUFRVZkdLTkNGZkNJM2JwRkgyVXdidk56SkQ2d25pVzVDOXJPRzdvQk1TYkRUT0sySEpLXzNtZjFEaWZ6b0gwaVFZMnI1ZnlKem9tdFlEZDJaNEJHdFBuV3BVNndBRjNyY2ZPWXFZRFcxS0E3NFBzUFptMmthcUM3SWNxMVB2cUZnbFgzUXdwbXZRcXBFdnpXU05TM25ORnVpNXlqdXBrSFNsWGZVMjRDRW4zRUEifSx7Imp3dCI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoxY213aU9pSm9kSFJ3Y3pvdkwyRmhMblpwY25SeWRTNWpiMjB2WVhSMGNpOXpkWEJsY2kxaFpHMXBiaTkyWVd4MVpTOTBjblZsSWl3aWJtRnRaU0k2ZEhKMVpTd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5wa3ZBdlJ4VTNwY3FUQ3ZVQ3VKdEN3RWc4VW5Ya0xHS1VnZEg3YUJuSFdxQ2l4X0NYdF9PcUo1VC1iNTh4bHN6ZWx5dmNkbXZUUXh5ZzFfYUhYT0tnNXdEUVFhQTZVcjNOc2JZcjNvc2tyUEk4ZEU4Z0lLMzI2TlBwcXJqcnBCR0dYa1BvSkhrWHdHTzVHZnF0b05wdUZXZDhZNVVETG1IMVFLZWdzQkpRQVZvVjZKcFdHdlB5UF9hcEFMOGNOUE5pVEh1QUwyUnlFMTdBcmh6aUh1NlVqYXFfZmFKYUM4c2doU2VqR2pXNlNwZFdpU0Y5S3cwclY0ZFpXalJzUnU5cWJXZjNnck1JTXFFb1AtM21TbHB4aHBEUFdUUzBoUmFDblN2cG5lUXluRnZoYktNQTJYQTB6MjlaOWk2SnVlUWlzcmpLVkoxUGlhWXZaSVdOenozT0EifV0sInB1YmxpY0tleSI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVPMG54aEdDeXVFYkhPcU5YaldJXG4yZGZ1TkM5ano2SjlaS2IzZHZvc1pMdGlybzMyK2pnZWV1ZGNPMC9sMVArUnpHa09SVUd1YnJrTi9vVVd0QzlsXG5ESmdxM1QwNXBRSlVjZy8rc2J5TDFHdlVuVTBpSmZWazl6ejV3M2NEQkUvSTk5ckNHc0lmRzJtK3VuS0tKbjIyXG53ZC9aT3FRRE93Wk42b0RrQjdaV1FKZTBRQlF1YjBsSmpUaG9nclBWaVhJSnFSZ1RvSCt0c2pVWCtodGtwOFFBXG52dmt3MDlYYzFIWjZraFpWZGZZZjdCbTBZSTBPVkNNYko3N0JWc01HMGNDc0QvOGgzLzI2RjdvcTl1aWFlVG54XG5zWkJzemZCWEpHcFVtNDBuYWFRSi80Q0lxMjBRVGFkclhMTXAxQ1JNblI1VGNlTHZ2L0twR2xRR1hiNFY0elJmXG5xUUlEQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tIiwiYWxpYXNlcyI6W10sImlhdCI6MTU1MzQ4NTI0NywiZXhwIjoxNTUzNTcxNjQ3fQ.mh1ub1kS9WryrLGj3ONFmk6EGl6rPE29VJU21O3IX4EslCkxmIMVVjpFf8s83uFkyy7c2w5Re6NJsln9FHgLTV7RKqdj71U6tE7onh6l8_ZBNPCdetrCcrMCFac65k67_Lz5XM4BVPyCvNuoe-gY8FkeqyimQzkL6Q52HNG2FpslDrgcx50HiCC_aX638UyyB3W4n7J4uF8LrLzsNqyXb2xQw9BVVBJ9-XmXUgOmFaMMG5wJyxFETpP9yR3YBCwiZw911tc5CC738ho4IufdX98HBPqECMIkoL4ZJmfVw4N7YlbaJDU5WZa2rqCpgmvn_B4Zlv1QnVf41fj4EOifyg\",\n"
                                             "\n"
                                             "    \"publicKey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\\nqQIDAQAB\\n-----END PUBLIC KEY-----\", \n"
                                             "    \n"
                                             "    \"signerPublicKey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\\nqQIDAQAB\\n-----END PUBLIC KEY-----\", \n"
                                             "    \n"
                                             "    \"userId\": \"sreddy@virtrudeploy.us\"\n"
                                             "}";
        auto entityObject = EntityObject::createEntityObjectFromJson(entityObjectJsonStr);

        try {
            std::string dummpyKey{"dummy"};
            PolicyObject policyObject;
            policyObject.addDissem(user());
            auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user()));
            auto tdf =  tdfbuilderPtr->setKasUrl(kasUrl)
                    .setEasUrl(easUrl)
                    .setKasPublicKey(dummpyKey)
                    .setEntityObject(entityObject)
                    .setMetaData({{"displayName", "sdk-test.pdf"}})
                    .setHttpHeaders(headers)
                    .setPolicyObject(policyObject).build();

            BOOST_TEST_MESSAGE("TDF basic test passed.");
        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
            std::cout << "virtru exception " << exception.what() << std::endl;
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std::cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std::cout << "Unknown..." << std::endl;
        }
    }

    BOOST_AUTO_TEST_CASE(test_tdf_builder_advanced) {

        class ExternalLogger : public ILogger {
        public:

            /// A callback interface for log messages.
            void TDFSDKLog(LogMessage logMessage) override {

                std::ostringstream os;
                std::time_t timeInSeconds = (logMessage.timestamp/1000);
                std::size_t fractionalSeconds = (logMessage.timestamp % 1000);
                os << "[" << std::put_time(std::localtime(&timeInSeconds), "%m-%d-%Y %X") << "." << fractionalSeconds << "]";
                std::string logTime = os.str();

                switch (logMessage.level) {
                    case LogLevel::Trace:
                        std::clog << logTime << "[Trace] " << logMessage.message << std::endl;
                        BOOST_FAIL("Testing external logger - Failed(log level is Info)");
                        break;

                    case LogLevel::Debug:
                        std::clog << logTime << "[Debug] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Debug));
                        break;

                    case LogLevel::Info:
                        std::clog << logTime << "[Info] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Info));
                        break;

                    case LogLevel::Warn:
                        std::clog << logTime << "[Warn] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Warn));
                        break;

                    case LogLevel::Error:
                        std::clog << logTime << "[Error] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Error));
                        break;

                    case LogLevel::Fatal:
                        std::clog << logTime << "[Fatal] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Fatal));
                        break;
                }
            }
        };

        std::shared_ptr<ExternalLogger> externalLogger = std::make_shared<ExternalLogger>();
        auto keyPairOf2048 = crypto::RsaKeyPair::Generate(2048);
        std::string kasPublicKey = keyPairOf2048->PublicKeyInPEMFormat();
        std::string publicKey = keyPairOf2048->PublicKeyInPEMFormat();
        EntityObject entityObject{};

#if TEST_ENCRYPT_DECRYPT
        kasPublicKey = getKasPublicKey();
        entityObject = getEntityObject(publicKey);
#endif
        std::ostringstream authHeaderValue;
        authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
        HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                {kVirtruClientKey, VirtruClientKey},
                                {kAuthorizationKey, authHeaderValue.str()}};

        auto policyObject = PolicyObject{};
        policyObject.addDissem(user());

        // Store the uuid for later verification.
        auto policyUuid = policyObject.getUuid();

        try {
#if TEST_ENCRYPT_DECRYPT
            { // Remote
                std::unordered_map<std::string, std::string> metaData;
                metaData.insert({"displayName", "sdk-test.pdf"});
                metaData.insert({"fileProvider", "tdf-cpp-sdk"});

                std::string mimeType{"application/pdf"};

                auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();
                auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user()));
                auto tdf = tdfbuilderPtr->setKasUrl(kasUrl)
                        .setEasUrl(easUrl)
                        .setHttpHeaders(headers)
                        .setExternalLogger(externalLogger, LogLevel::Debug)
                        .setDefaultSegmentSize(2 * 1024 * 1024)
                        .setMetaData(metaData)
                        .setKasPublicKey(kasPublicKey)
                        .setPrivateKey(keyPairOf2048->PrivateKeyInPEMFormat())
                        .setPublicKey(publicKey)
                        .setEntityObject(entityObject)
                        .setEncryptionObject(KeyType::split, CipherType::Aes256GCM)
                        .setIntegrityAlgorithm(IntegrityAlgorithm::HS256, IntegrityAlgorithm::GMAC)
                        .setKeyAccessType(KeyAccessType::Remote)
                        .setPayloadMimeType(mimeType)
                        .setPolicyObject(policyObject)
                        .setHTTPServiceProvider(httpServiceProvider).build();


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

                tdf->encryptFile(inPathEncrypt, outPathEncrypt);

                auto tdfPolicyUuid = tdf->getPolicyUUID(outPathEncrypt);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                std::cout << std::endl;

                tdf->decryptFile(inPathDecrypt, outPathDecrypt);
            }

            { // Wrapper with no meta data

                // TODO: These tests are using Virtru KAS instead of Core KAS. Virtru KAS expect the metadata so
                // we need pass the meta information.
                std::unordered_map<std::string, std::string> metaData;
                metaData.insert({"displayName", "sdk-test.pdf"});
                metaData.insert({"fileProvider", "tdf-cpp-sdk"});

                auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();
                auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user()));
                auto tdf = tdfbuilderPtr->setKasUrl(kasUrl)
                        .setEasUrl(easUrl)
                        .setHttpHeaders(headers)
                        .setExternalLogger(externalLogger, LogLevel::Debug)
                        .setDefaultSegmentSize(2 * 1024 * 1024)
                        .setKasPublicKey(kasPublicKey)
                        .setPrivateKey(keyPairOf2048->PrivateKeyInPEMFormat())
                        .setPublicKey(publicKey)
                        .setMetaData(metaData)
                        .setEntityObject(entityObject)
                        .setEncryptionObject(KeyType::split, CipherType::Aes256GCM)
                        .setIntegrityAlgorithm(IntegrityAlgorithm::HS256, IntegrityAlgorithm::GMAC)
                        .setKeyAccessType(KeyAccessType::Wrapped)
                        .setPolicyObject(policyObject)
                        .setHTTPServiceProvider(httpServiceProvider).build();


                std::string currentDir = getCurrentWorkingDir();

                // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
                std::string inPathEncrypt {currentDir };
                inPathEncrypt.append("\\data\\sample.pdf");

                std::string outPathEncrypt {currentDir };
                outPathEncrypt.append("\\data\\encrypt\\sample-wrapped.pdf.tdf");

                std::string inPathDecrypt {currentDir };
                inPathDecrypt.append("\\data\\encrypt\\sample-wrapped.pdf.tdf");

                std::string outPathDecrypt {currentDir };
                outPathDecrypt.append("\\data\\decrypt\\sample-wraped.pdf");

#else
                std::string inPathEncrypt{currentDir};
                inPathEncrypt.append("/data/sample.pdf");

                std::string outPathEncrypt{currentDir};
                outPathEncrypt.append("/data/encrypt/sample-wrapped.pdf.tdf");

                std::string inPathDecrypt{currentDir};
                inPathDecrypt.append("/data/encrypt/sample-wrapped.pdf.tdf");

                std::string outPathDecrypt{currentDir};
                outPathDecrypt.append("/data/decrypt/sample-wrapped.pdf");
#endif

                tdf->encryptFile(inPathEncrypt, outPathEncrypt);

                auto tdfPolicyUuid = tdf->getPolicyUUID(outPathEncrypt);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                // Lazy sync the policy.
                tdf->sync(outPathEncrypt);

                std::cout << std::endl;

                tdf->decryptFile(inPathDecrypt, outPathDecrypt);
            }
#endif
            BOOST_TEST_MESSAGE("TDF basic test passed.");
        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }


    BOOST_AUTO_TEST_CASE(test_tdf_builder_html_tdfs) {

        try {

            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();

            std::string currentDir = getCurrentWorkingDir();
#if TEST_ENCRYPT_DECRYPT

            {
                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);
                tdfBuilder->enableConsoleLogging(LogLevel::Debug);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

#ifdef _WINDOWS
                std::string inPathEncrypt {currentDir };
                inPathEncrypt.append("\\data\\sample.pdf");

                std::string outPathEncrypt {currentDir };
                outPathEncrypt.append("\\data\\encrypt\\sample.pdf.html");

                std::string inPathDecrypt {currentDir };
                inPathDecrypt.append("\\data\\encrypt\\sample.pdf.html");

                std::string outPathDecrypt {currentDir };
                outPathDecrypt.append("\\data\\decrypt\\sample.pdf");
#else
                std::string inPathEncrypt{currentDir};
                inPathEncrypt.append("/data/sample.pdf");

                std::string outPathEncrypt{currentDir};
                outPathEncrypt.append("/data/encrypt/sample.pdf.html");

                std::string inPathDecrypt{currentDir};
                inPathDecrypt.append("/data/encrypt/sample.pdf.html");

                std::string outPathDecrypt{currentDir};
                outPathDecrypt.append("/data/decrypt/sample.pdf");
#endif

                tdf->encryptFile(inPathEncrypt, outPathEncrypt);

                auto tdfPolicyUuid = tdf->getPolicyUUID(outPathEncrypt);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                std::cout << std::endl;

                tdf->decryptFile(inPathDecrypt, outPathDecrypt);
            }

            { // Wrapper with no meta data

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Html);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);
                auto tdf = tdfBuilder->build();

                // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
                std::string inPathEncrypt {currentDir };
                inPathEncrypt.append("\\data\\sample.pdf");

                std::string outPathEncrypt {currentDir };
                outPathEncrypt.append("\\data\\encrypt\\sample-wrapped.pdf.html");

                std::string inPathDecrypt {currentDir };
                inPathDecrypt.append("\\data\\encrypt\\sample-wrapped.pdf.html");

                std::string outPathDecrypt {currentDir };
                outPathDecrypt.append("\\data\\decrypt\\sample-wraped.pdf");

#else
                std::string inPathEncrypt{currentDir};
                inPathEncrypt.append("/data/sample.pdf");

                std::string outPathEncrypt{currentDir};
                outPathEncrypt.append("/data/encrypt/sample-wrapped.pdf.html");

                std::string inPathDecrypt{currentDir};
                inPathDecrypt.append("/data/encrypt/sample-wrapped.pdf.html");

                std::string outPathDecrypt{currentDir};
                outPathDecrypt.append("/data/decrypt/sample-wrapped.pdf");
#endif

                tdf->encryptFile(inPathEncrypt, outPathEncrypt);

                auto tdfPolicyUuid = tdf->getPolicyUUID(outPathEncrypt);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                // Lazy sync the policy.
                tdf->sync(outPathEncrypt);

                std::cout << std::endl;

                tdf->decryptFile(inPathDecrypt, outPathDecrypt);
            }
#endif
            BOOST_TEST_MESSAGE("TDF basic test passed.");
        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }

    BOOST_AUTO_TEST_CASE(test_tdf_builder_RCA_tdf_type) {

        try {

            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()},
                                    { "Authorization-User", user()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();

#if TEST_ENCRYPT_DECRYPT
            { // Remote using tdf to encrypt stream

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Zip);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());
                policyObject.addDissem("sujankota@gmail.com");
                policyObject.addDissem("dricaud@virtru.com");
                policyObject.addDissem("ricaud512@gmail.com");

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

//                const size_t sizeOfData = 25 * 1024 * 1024; // 25 mb
//                static std::vector<gsl::byte> plainData(sizeOfData);
//                std::fill(plainData.begin(), plainData.end(), gsl::byte(0xFF));

                static std::string plainData{"Hello World!"};
                static std::vector<gsl::byte> decryptedBuffer;

                { // Encrypt with I/O Providers
                    struct CustomInputProvider : IInputProvider {
                        void readBytes(size_t index, size_t length, WriteableBytes &bytes) override {
                            std::memcpy(bytes.data(), plainData.data() + index, length);
                        }

                        size_t getSize() override { return plainData.size(); }
                    };

                    struct CustomOutputProvider: IOutputProvider {
                        void writeBytes(Bytes bytes) override {
                            decryptedBuffer.insert(decryptedBuffer.end(), bytes.begin(), bytes.end());
                        }
                        void flush() override { /* Do nothing */ }
                    };


                    CustomInputProvider inputProvider{};

                    auto upsertResponse = tdf->encryptInputProviderToRCA(inputProvider);

                    std::cout << "Upsert Response:" << upsertResponse << std::endl;
                    nlohmann::json upsertResponseObj;
                    try{
                        upsertResponseObj = nlohmann::json::parse(upsertResponse);
                    } catch (...){
                        if (upsertResponseObj == ""){
                            ThrowException("No rewrap response from KAS", VIRTRU_NETWORK_ERROR);
                        }
                        else{
                            ThrowException("Could not parse KAS rewrap response: " + boost::current_exception_diagnostic_information() + "  with response: ", VIRTRU_NETWORK_ERROR);
                        }
                    }

                    CustomOutputProvider outputProvider{};
                    std::string downloadUrl = upsertResponseObj["downloadUrl"];
                    std::string kek = upsertResponseObj["kek"];
                    tdf->decryptRCAToOutputProvider(downloadUrl, kek, outputProvider);

                    std::string decryptedMessage(reinterpret_cast<const char *>(&decryptedBuffer[0]), decryptedBuffer.size());
                    BOOST_TEST(plainData == decryptedMessage);

                    std::cout << "Dectypyed data:" << decryptedBuffer.size() << std::endl;
                }
            }
#endif

        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }
    }

    BOOST_AUTO_TEST_CASE(test_tdf_builder_stream_tdf_type) {

        try {

            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();

#if TEST_ENCRYPT_DECRYPT
            { // Remote using tdf to encrypt stream

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Zip);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                // Create simple string.
                std::string plainText{"HelloWorld!!"};
                std::istringstream inputStream(plainText);
                std::stringstream ioStream; // will be used as input and output stream

                // encrypt the stream.
                tdf->encryptStream(inputStream, ioStream);

                auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                { // Write to a file and test decrypt

                    // Write the .tdf stream to file.
                    std::string tdfFile{"simple.txt.tdf"};
                    std::ofstream outFileStream{tdfFile, std::ios_base::out | std::ios_base::binary};
                    if (!outFileStream) {
                        BOOST_FAIL("Failed to open file for writing.");
                    }

                    outFileStream << ioStream.str();
                    outFileStream.close();

                    // decrypt the file
                    std::string outTxtFile{"simple.txt"};
                    tdf->decryptFile(tdfFile, outTxtFile);

                    std::ifstream inputFileStream(outTxtFile);
                    std::string decryptedText((std::istreambuf_iterator<char>(inputFileStream)),
                                              std::istreambuf_iterator<char>());
                    BOOST_TEST(plainText == decryptedText);
                }

                std::ostringstream decryptedStream;
                tdf->decryptStream(ioStream, decryptedStream);
                std::string decryptedText = decryptedStream.str();

                BOOST_TEST(plainText == decryptedText);
            }

            { // Wrapper with no meta data

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Zip);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                // Create simple string.
                std::string plainText{"HelloWorld!!"};
                std::istringstream inputStream(plainText);
                std::stringstream ioStream; // will be used as input and output stream

                // encrypt the stream.
                tdf->encryptStream(inputStream, ioStream);

                auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                {
                    // Write the .tdf stream to file.
                    std::string tdfFile{"simple-wrapped.txt.tdf"};
                    std::ofstream outFileStream{tdfFile, std::ios_base::out | std::ios_base::binary};
                    if (!outFileStream) {
                        BOOST_FAIL("Failed to open file for writing.");
                    }

                    outFileStream << ioStream.str();
                    outFileStream.close();

                    // decrypt the file
                    std::string outTxtFile{"simple-wrapped.txt"};
                    tdf->decryptFile(tdfFile, outTxtFile);

                    std::ifstream inputFileStream(outTxtFile);
                    std::string decryptedText((std::istreambuf_iterator<char>(inputFileStream)),
                                              std::istreambuf_iterator<char>());
                    BOOST_TEST(plainText == decryptedText);
                }

                std::ostringstream decryptedStream;
                tdf->decryptStream(ioStream, decryptedStream);
                std::string decryptedText = decryptedStream.str();

                BOOST_TEST(plainText == decryptedText);

            }

            BOOST_TEST_MESSAGE("TDF streaming test passed using zip format.");
#endif

        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }

    BOOST_AUTO_TEST_CASE(test_tdf_builder_stream_html_type) {

        try {

            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();


#if TEST_ENCRYPT_DECRYPT
            { // Remote

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                // Create simple string.
                std::string plainText{"HelloWorld!!"};
                std::istringstream inputStream(plainText);
                std::stringstream ioStream;

                // encrypt the stream.
                tdf->encryptStream(inputStream, ioStream);

                auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                {
                    // Write the .tdf stream to file.
                    std::string tdfFile{"simple-html.txt.html"};
                    std::ofstream outFileStream{tdfFile, std::ios_base::out | std::ios_base::binary};
                    if (!outFileStream) {
                        BOOST_FAIL("Failed to open file for writing.");
                    }

                    outFileStream << ioStream.str();
                    outFileStream.close();

                    // decrypt the file
                    std::string outTxtFile{"simple-html.txt"};
                    tdf->decryptFile(tdfFile, outTxtFile);

                    std::ifstream inputFileStream(outTxtFile);
                    std::string decryptedText((std::istreambuf_iterator<char>(inputFileStream)),
                                              std::istreambuf_iterator<char>());
                    BOOST_TEST(plainText == decryptedText);
                }

                std::ostringstream decryptedStream;
                tdf->decryptStream(ioStream, decryptedStream);
                std::string decryptedText = decryptedStream.str();

                BOOST_TEST(plainText == decryptedText);
            }

            { // Wrapper with no meta data

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Html);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();


                // Create simple string.
                std::string plainText{"HelloWorld!!"};
                std::istringstream inputStream(plainText);
                std::stringstream ioStream;

                // encrypt the stream.
                tdf->encryptStream(inputStream, ioStream);

                auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                {
                    // Write the .tdf stream to file.
                    std::string tdfFile{"simple-html-wrapped.txt.html"};
                    std::ofstream outFileStream{tdfFile, std::ios_base::out | std::ios_base::binary};
                    if (!outFileStream) {
                        BOOST_FAIL("Failed to open file for writing.");
                    }

                    outFileStream << ioStream.str();
                    outFileStream.close();

                    // decrypt the file
                    std::string outTxtFile{"simple-html-wrapped.txt"};
                    tdf->decryptFile(tdfFile, outTxtFile);

                    std::ifstream inputFileStream(outTxtFile);
                    std::string decryptedText((std::istreambuf_iterator<char>(inputFileStream)),
                                              std::istreambuf_iterator<char>());
                    BOOST_TEST(plainText == decryptedText);
                }

                std::ostringstream decryptedStream;
                tdf->decryptStream(ioStream, decryptedStream);
                std::string decryptedText = decryptedStream.str();

                BOOST_TEST(plainText == decryptedText);
            }

            BOOST_TEST_MESSAGE("TDF streaming test passed using html format.");
#endif

        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }


    BOOST_AUTO_TEST_CASE(test_tdf_builder_16mb_stream_tdf_type) {

        try {

            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();

#if TEST_ENCRYPT_DECRYPT
            { // Remote using tdf to encrypt stream


                std::string currentDir = getCurrentWorkingDir();

                // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
                std::string inPathEncrypt {currentDir };
                inPathEncrypt.append("\\data\\sample.pdf");
#else
                std::string inPathEncrypt{currentDir};
                inPathEncrypt.append("/data/sample.pdf");
#endif

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Zip);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                // Create a stream for 16mb file.
                std::ifstream inputStream{inPathEncrypt, std::ios_base::out | std::ios_base::binary};
                std::stringstream ioStream; // will be used as input and output stream

                std::string fileContents { std::istreambuf_iterator<char>(inputStream), std::istreambuf_iterator<char>() };

                // encrypt the stream.
                tdf->encryptStream(inputStream, ioStream);

                auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                std::ostringstream decryptedStream;
                tdf->decryptStream(ioStream, decryptedStream);
                std::string decryptedText = decryptedStream.str();

                BOOST_TEST(fileContents == decryptedText);
            }

            BOOST_TEST_MESSAGE("TDF streaming(16 mb) test passed using zip format.");
#endif
        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }

    BOOST_AUTO_TEST_CASE(test_tdf_builder_16mb_stream_html_type) {

        try {

            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();

#if TEST_ENCRYPT_DECRYPT
            { // Remote using tdf to encrypt stream


                std::string currentDir = getCurrentWorkingDir();

                // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
                std::string inPathEncrypt {currentDir };
                inPathEncrypt.append("\\data\\sample.pdf");
#else
                std::string inPathEncrypt{currentDir};
                inPathEncrypt.append("/data/sample.pdf");
#endif

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                // Create a stream for 16mb file.
                std::ifstream inputStream{inPathEncrypt, std::ios_base::out | std::ios_base::binary};
                std::stringstream ioStream; // will be used as input and output stream

                std::string fileContents { std::istreambuf_iterator<char>(inputStream), std::istreambuf_iterator<char>() };

                // encrypt the stream.
                tdf->encryptStream(inputStream, ioStream);

                auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
                BOOST_TEST(tdfPolicyUuid == policyUuid);

                std::ostringstream decryptedStream;
                tdf->decryptStream(ioStream, decryptedStream);
                std::string decryptedText = decryptedStream.str();

                BOOST_TEST(fileContents == decryptedText);
            }

            BOOST_TEST_MESSAGE("TDF streaming(16 mb) test passed using zip format.");
#endif
        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }


    BOOST_AUTO_TEST_CASE(test_tdf_builder_callback_tdf_type) {

        try {
            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();

#if TEST_ENCRYPT_DECRYPT
            { // Remote using tdf to encrypt stream

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Zip);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                tdf = tdfBuilder->build();

                testSourceAndSinkInterface(tdf.get());
            }

            { // Wrapper with no meta data

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Zip);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                testSourceAndSinkInterface(tdf.get());
            }

            BOOST_TEST_MESSAGE("TDF streaming test passed using zip format.");
#endif

        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }

    BOOST_AUTO_TEST_CASE(test_tdf_builder_callback_html_type) {

        try {

            std::ostringstream authHeaderValue;
            authHeaderValue << "Virtru [" << R"([")" << appId() << R"(",")" <<  user() << R"("])" << "]";
            HttpHeaders headers = { {kUserAgentKey, UserAgentValuePostFix},
                                    {kVirtruClientKey, VirtruClientKey},
                                    {kAuthorizationKey, authHeaderValue.str()}};

            auto httpServiceProvider = std::make_shared<HTTPServiceProvider>();

#if TEST_ENCRYPT_DECRYPT
            { // Remote

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                testSourceAndSinkInterface(tdf.get());
            }

            { // Wrapper with no meta data

                auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Html);
                tdfBuilder->setHttpHeaders(headers).setHTTPServiceProvider(httpServiceProvider);

                auto policyObject = PolicyObject{};
                policyObject.addDissem(user());

                // Store the uuid for later verification.
                auto policyUuid = policyObject.getUuid();

                tdfBuilder->setPolicyObject(policyObject);

                auto tdf = tdfBuilder->build();

                testSourceAndSinkInterface(tdf.get());
            }

            BOOST_TEST_MESSAGE("TDF streaming test passed using html format.");
#endif

        }  catch ( const Exception& exception) {
            BOOST_FAIL(exception.what());
        }  catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std :: cout << "Unknown..." << std::endl;
        }

    }

BOOST_AUTO_TEST_SUITE_END()