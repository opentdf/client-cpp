//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/28.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_key_access_object_suite

#include "asym_decryption.h"
#include "asym_encryption.h"
#include "crypto/bytes.h"
#include "crypto/crypto_utils.h"
#include "crypto/rsa_key_pair.h"
#include "entity_object.h"
#include "logger.h"
#include "network/http_client_service.h"
#include "mock_network_interface.h"
#include "policy_object.h"
#include "sdk_constants.h"
#include "tdf.h"
#include "tdf_exception.h"
#include "tdf_logging_interface.h"
#include "tdfbuilder.h"

#include <boost/filesystem.hpp>
#include <boost/test/included/unit_test.hpp>
#include <iostream>
#include <stdio.h>
#include "nlohmann/json.hpp"

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#define TEST_ENCRYPT_DECRYPT 1
#define ENABLE_TEST 0
//#define KAS_LOCALHOST

// TODO: Temporary place holder should be moved to virtru sdk.
// Update the appid and user for testing this code.
constexpr auto user = "tdf-user@virtrucanary.com";
constexpr auto kasUrl = "https://api-develop01.develop.virtru.com/kas";

// const auto OIDCAccessToken = R"(eyJhbGciOiJSUzI1NiIsInR5cCIg
// OiAiSldUIiwia2lkIiA6ICJGRjJKM0o5TjNGQWQ0dnpLVDd2aEloZE1DTEVudE1PejVtLWhGNm5ScFNZIn0.
// eyJleHAiOjE2MTQxMTgzNzgsImlhdCI6MTYxNDExODA3OCwianRpIjoiNWQ4OTczYjYtYjg5Yy00OTBjLWIz
// YTYtMTM0ZDMxOTYxZTM3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL2V4YW1w
// bGUtcmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiN2ZkZGJkYWQtNDlmYS00NWU4LTg4MzItMzI3ZGI4
// ZjU1MDE1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZXhhbXBsZS1yZWFsbS1jbGllbnQiLCJzZXNzaW9uX3N0
// YXRlIjoiOTA0MTc4NTAtNWEwNC00ZmU1LTgxZWMtOTkzZDY1MmVhYmY5IiwiYWNyIjoiMSIsInJlYWxtX2Fj
// Y2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJj
// ZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50
// LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic3VwaXJpIjoidG9r
// ZW5fc3VwaXJpIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGFpbSI6eyJuYW1lIjp7InVzZXJuYW1lIjoi
// Zm9vIn19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqZWZmNS1leGFtcGxlIn0.NfM272HpLfyHACNJrXniyPF5
// klXjfB8QbhHBt_aTlZUF1-wO7W4-3qL02bMYe71dg_swR5WLFR0SL-zqa9zeKfsegL8E-lEeRSCcFwTvoSXP
// XSZ06tafFmSNxuA88MogG_3ZBhi9sUL5uAXtCoC3Rkb6xpb-JdHp42n68s_Mm1teCU2wx2rS6O1k23YCK3lY
// _xRsmV62sQ_tx973N5u7YHPxWsKVi-gHNlW3N0x23bRsEk-qcIq-3ug5cLOyADlNUeApTmug9lXGJxqxo3jl
// ugnuf6VUtMwI1x8xSbePwC1pmGAfzZX2pS0kEUiGSHdH7flzibrMG70IXlutmS3e8Q)";

using namespace virtru::network;
using namespace virtru::crypto;
using namespace virtru;

#if TEST_ENCRYPT_DECRYPT

std::string getCurrentWorkingDir() {
    char buff[FILENAME_MAX];
    GetCurrentDir(buff, FILENAME_MAX);
    std::string current_working_dir(buff);
    return current_working_dir;
}

HttpHeaders GetHeaders() {
    std::ostringstream authHeaderValue;
    HttpHeaders headers = {{kContentTypeKey, kContentTypeJsonValue}};
    return headers;
}

std::string ReplaceAll(std::string str, const std::string &from, const std::string &to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

typedef std::tuple<const std::string, const std::string> keyPair;

//We do this a lot
keyPair GetKeypair() {
    auto keyPairOf4096 = RsaKeyPair::Generate(4096);
    auto privateKey = keyPairOf4096->PrivateKeyInPEMFormat();
    auto publicKey = keyPairOf4096->PublicKeyInPEMFormat();
    return {publicKey, privateKey};
}

void SourceAndSinkInterfaceEncrypt(TDF *tdf, std::string plainText, std::stringstream *ioStream, ByteArray<5> *buffer) {
    // ByteArray<5> buffer;
    std::istringstream inputStream(plainText);
    auto encryptSourceCB = [&inputStream, buffer](virtru::Status &status) -> BufferSpan {
        if (inputStream.read(toChar(buffer->data()), buffer->size())) {
            status = Status::Success;
            return {(const std::uint8_t *)buffer->data(), buffer->size()};
            ;
        } else if (inputStream.eof()) {
            status = Status::Success;
            return {(const std::uint8_t *)buffer->data(), static_cast<std::size_t>(inputStream.gcount())};
        } else {
            status = virtru::Status::Failure;
            return {nullptr, 0};
        }
    };

    auto encryptSinkCB = [ioStream](BufferSpan bufferSpan) {
        if (!(ioStream->write((const char *)(bufferSpan.data), bufferSpan.dataLength)))
            return Status::Failure;
        else
            return virtru::Status::Success;
    };

    tdf->encryptData(encryptSourceCB, encryptSinkCB);
}

void SourceAndSinkInterfaceDecrypt(TDF *tdf, std::string plainText, std::stringstream *ioStream, ByteArray<5> *buffer) {
    auto decryptSourceCB = [&ioStream, buffer](virtru::Status &status) -> BufferSpan {
        if (ioStream->read(toChar(buffer->data()), buffer->size())) {
            status = Status::Success;
            return {(const std::uint8_t *)buffer->data(), buffer->size()};
            ;
        } else if (ioStream->eof()) {
            status = Status::Success;
            return {(const std::uint8_t *)buffer->data(), static_cast<std::size_t>(ioStream->gcount())};
        } else {
            status = virtru::Status::Failure;
            return {nullptr, 0};
        }
    };

    std::string decryptedText;
    auto decryptSinkCB = [&decryptedText](BufferSpan bufferSpan) {
        decryptedText.append((const char *)bufferSpan.data, bufferSpan.dataLength);
        return virtru::Status::Success;
    };

    tdf->decryptData(decryptSourceCB, decryptSinkCB);
    BOOST_TEST(plainText == decryptedText);
}

std::unique_ptr<TDFBuilder> createTDFBuilder(LogLevel logLevel, KeyAccessType keyAccessType, Protocol protocol, keyPair kasKeys, keyPair clientKeys) {

    auto headers = GetHeaders();

    std::string mimeType{"text/plain"};

    std::unordered_map<std::string, std::string> metaData;
    metaData.insert({"displayName", "tdf-cpp-unit-tests"});
    metaData.insert({"fileProvider", "tdf-cpp-sdk"});

    auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user));

    tdfbuilderPtr->setKasUrl(kasUrl)
        .setKasPublicKey(std::get<0>(kasKeys))
        .setHttpHeaders(headers)
        .enableConsoleLogging(logLevel)
        .setDefaultSegmentSize(2 * 1024 * 1024)
        .setPrivateKey(std::get<1>(clientKeys))
        .setPublicKey(std::get<0>(clientKeys))
        .enableOIDC(true)
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
        std::string htmlTemplateFilepath{currentDir};

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

#endif //TEST_ENCRYPT_DECRYPT

//This suite tests OIDC and KAS v2 endpoints specifically.
BOOST_AUTO_TEST_SUITE(test_tdf_builder_v2_suite)



using namespace virtru;

//This simply simulates a KAS rewrap operation (decrypt wrapped key wiht Kas privkey, rewrap/encrypt with client pubkey)
//for testing/mock purposes
static std::string FauxKASKeyRewrap(const std::string clientWrappedKey, const std::string kasPrivKey, const std::string clientPubKey) {
    // std::cout << "Kas privkey for test: " << kasPrivKey << std::endl;
    auto kasDecoder = AsymDecryption::create(kasPrivKey);
    std::vector<gsl::byte> unwrapBuffer(kasDecoder->getOutBufferSize());
    auto unwrapWriteBuf = toWriteableBytes(unwrapBuffer);
    kasDecoder->decrypt(toBytes(clientWrappedKey), unwrapWriteBuf);
    WrappedKey wrappedKey;
    std::copy(unwrapWriteBuf.begin(), unwrapWriteBuf.end(), wrappedKey.begin());

    // std::cout << "Unwrapped key (b64)" << base64Encode(toBytes(wrappedKey)) << std::endl;

    //Now do rewrap
    auto encoder = AsymEncryption::create(clientPubKey);
    std::vector<gsl::byte> outBuffer(encoder->getOutBufferSize());
    auto writeableBytes = toWriteableBytes(outBuffer);
    encoder->encrypt(toBytes(wrappedKey), writeableBytes);
    // std::cout << "Rewrapped key (b64)" << base64Encode(writeableBytes) << std::endl;
    return base64Encode(writeableBytes);
}

static std::string BuildFakedRewrapResponse(
    const std::string precedingUpsertRequest,
    std::tuple<std::string, std::string> kasKeypair,
    std::tuple<std::string, std::string> clientKeypair) {

    auto parsedBody = nlohmann::json::parse(precedingUpsertRequest);

    std::string wrappedKeyAsStr = parsedBody[kKeyAccess][kWrappedKey];
    auto decodedWrappedKey = base64Decode(wrappedKeyAsStr);

    auto rewrappedKey = FauxKASKeyRewrap(decodedWrappedKey, std::get<1>(kasKeypair), std::get<0>(clientKeypair));

    const auto fakedRewrapResponseJSON =
        R"({
                    "entityWrappedKey": "",
                    "kasWrappedKey":"RFnrVDn9NpbbCOclNNWt1nsiz3Amu1px9l2OMPy85asiFEVCUkdD/DgVKavbsqg50Ku6Ldlf5WCx9tiiKFeMuVNI8/8NenHduPE6qf85/Jvc2Ix8TziCq6zJHU7eDyz2QprnD2bY03lpTT6K0qoSAiaU8qq2TFhLlYQMRiD0a/ORV4VkyCGMFjfnP7YyE/Gg6RsTfpsaCzva37Njcky6SNY6zb//e7f4rp9x/zy4lZRjd4RGSHNH8tTCS9z0S4w5mhXfsV66am3S8LHNAnSKCM4cjptFMu7gtr5z9eLgVdplX06pUswG+0zYaNhP/1Nu/t+ClOzzPTxW7/hcaTT+Zw==",
                    "metadata":{
                        "acmContract":{
                            "accessCount":0,
                            "accessPercent":"0.00",
                            "accessedBy":[
                            ],
                            "attributes":[
                            ],
                            "authorizations":[
                            ],
                            "authorizedUser":"tdf-user@virtrucanary.com",
                            "displayName":"sdk-test.pdf",
                            "forwardCount":0,
                            "isInternal":true,
                            "isManaged":false,
                            "isOwner":true,
                            "key":"4459eb5439fd3696db08e72534d5add67b22cf7026bb5a71f65d8e30fcbce5ab22144542524743fc381529abdbb2a839d0abba2dd95fe560b1f6d8a228578cb95348f3ff0d7a71ddb8f13aa9ff39fc9bdcd88c7c4f3882abacc91d4ede0f2cf6429ae70f66d8d379694d3e8ad2aa12022694f2aab64c584b95840c4620f46bf391578564c8218c1637e73fb63213f1a0e91b137e9b1a0b3bdadfb363724cba48d63acdbfff7bb7f8ae9f71ff3cb8959463778446487347f2d4c24bdcf44b8c399a15dfb15eba6a6dd2f0b1cd02748a08ce1c8e9b4532eee0b6be73f5e2e055da655f4ea952cc06fb4cd868d84fff536efedf8294ecf33d3c56eff85c6934fe67",
                            "keyAccess":{
                                "details":{
                                "body":"RFnrVDn9NpbbCOclNNWt1nsiz3Amu1px9l2OMPy85asiFEVCUkdD/DgVKavbsqg50Ku6Ldlf5WCx9tiiKFeMuVNI8/8NenHduPE6qf85/Jvc2Ix8TziCq6zJHU7eDyz2QprnD2bY03lpTT6K0qoSAiaU8qq2TFhLlYQMRiD0a/ORV4VkyCGMFjfnP7YyE/Gg6RsTfpsaCzva37Njcky6SNY6zb//e7f4rp9x/zy4lZRjd4RGSHNH8tTCS9z0S4w5mhXfsV66am3S8LHNAnSKCM4cjptFMu7gtr5z9eLgVdplX06pUswG+0zYaNhP/1Nu/t+ClOzzPTxW7/hcaTT+Zw==",
                                "encoding":"base64"
                                },
                                "keyId":"ae61e3bd-304c-48df-ad53-809c1518ccf3",
                                "type":"string",
                                "version":"3.0.0"
                            },
                            "leaseTime":60000,
                            "policyId":"2f0ff593-55ac-4ee7-ba23-8e246a7524da",
                            "recipientCount":0,
                            "sentFrom":"tdf-user@virtrucanary.com",
                            "state":"active",
                            "type":"file"
                        }
                    }
                })";

    auto rewrapResponse = nlohmann::json::parse(fakedRewrapResponseJSON);
    rewrapResponse[kEntityWrappedKey] = rewrappedKey;

    return rewrapResponse;
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_basic) {
#if ENABLE_TEST
    auto headers = GetHeaders();

    // constexpr auto entityObjectJsonStr = "{\n"
    //                                      "    \"aliases\": [\"sreddy@trusteddataformat.org\", \"sreddy@trusteddataformat.net\"], \n"
    //                                      "    \"attributes\": [\n"
    //                                      "        {\n"
    //                                      "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci91bmlxdWUtaWRlbnRpZmllci92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.qg8BYLJ6ZKu6e641_NLfjlghDwWexEr_YUCadUyPX-B1tonWIJUjGddhx2cz5H8Ldxpj0AurilCz2xAIcRItwm9-0M3RlNUAZ7l5wYahRnSWijwV4lL7Yvm_HwMYgrrVNvcUwj5cqpMREHfCDScS-lSb89zhq76dypVmkgmhZe3t9lD1fTSJKCJylc7X9AzbWzLc0fDQH702yU__ZVOVkBwTO2jJ4ovBDPB0w9LgCEZ-9pzvdUiTdYuhZ2PzQBTNHlK1xxQQCu148uuiTw8Fk_bs7efuGgUU7zfrKR2Lvgw5QLDpavL11HnXIKZihxzJbcrjBdKQCK0V7v3i7F2CkA\"\n"
    //                                      "        }, \n"
    //                                      "        {\n"
    //                                      "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9wcmltYXJ5LW9yZ2FuaXphdGlvbi92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.TBO2RbLIESO5h3n8Cop4DVYJNhI46nfaAIuzUuTJ73v5j0myplcj3amNyW_PPRxSauMhG5gwhkSrYHgnO-f423a7YnGW1SmfqmpEFd8s5j1yGRIytJsuaVD0B5nfrjSkS4Bu5lV8J2pYmnanZkr_Mo6oj2_IhITk0lVBTgri-PTUfGKNCFfCI3bpFH2UwbvNzJD6wniW5C9rOG7oBMSbDTOK2HJK_3mf1DifzoH0iQY2r5fyJzomtYDd2Z4BGtPnWpU6wAF3rcfOYqYDW1KA74PsPZm2kaqC7Icq1PvqFglX3QwpmvQqpEvzWSNS3nNFui5yjupkHSlXfU24CEn3EA\"\n"
    //                                      "        }, \n"
    //                                      "        {\n"
    //                                      "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9zdXBlci1hZG1pbi92YWx1ZS90cnVlIiwibmFtZSI6dHJ1ZSwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.pkvAvRxU3pcqTCvUCuJtCwEg8UnXkLGKUgdH7aBnHWqCix_CXt_OqJ5T-b58xlszelyvcdmvTQxyg1_aHXOKg5wDQQaA6Ur3NsbYr3oskrPI8dE8gIK326NPpqrjrpBGGXkPoJHkXwGO5GfqtoNpuFWd8Y5UDLmH1QKegsBJQAVoV6JpWGvPyP_apAL8cNPNiTHuAL2RyE17ArhziHu6Ujaq_faJaC8sghSejGjW6SpdWiSF9Kw0rV4dZWjRsRu9qbWf3grMIMqEoP-3mSlpxhpDPWTS0hRaCnSvpneQynFvhbKMA2XA0z29Z9i6JueQisrjKVJ1PiaYvZIWNzz3OA\"\n"
    //                                      "        }\n"
    //                                      "    ],\n"
    //                                      "     \n"
    //                                      "    \"cert\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJzcmVkZHlAdmlydHJ1ZGVwbG95LnVzIiwiYXR0cmlidXRlcyI6W3siand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5MWJtbHhkV1V0YVdSbGJuUnBabWxsY2k5MllXeDFaUzltWlRFelpqQm1ZUzB4Tm1VMUxUUTNaRFl0T0Rkall5MWhPVEkxTXpKaFl6Y3hZelFpTENKdVlXMWxJam9pWm1VeE0yWXdabUV0TVRabE5TMDBOMlEyTFRnM1kyTXRZVGt5TlRNeVlXTTNNV00wSWl3aWFXRjBJam94TlRVek5EZzFNalEzTENKbGVIQWlPakUxTlRNMU56RTJORGQ5LnFnOEJZTEo2Wkt1NmU2NDFfTkxmamxnaER3V2V4RXJfWVVDYWRVeVBYLUIxdG9uV0lKVWpHZGRoeDJjejVIOExkeHBqMEF1cmlsQ3oyeEFJY1JJdHdtOS0wTTNSbE5VQVo3bDV3WWFoUm5TV2lqd1Y0bEw3WXZtX0h3TVlncnJWTnZjVXdqNWNxcE1SRUhmQ0RTY1MtbFNiODl6aHE3NmR5cFZta2dtaFplM3Q5bEQxZlRTSktDSnlsYzdYOUF6Yld6TGMwZkRRSDcwMnlVX19aVk9Wa0J3VE8yako0b3ZCRFBCMHc5TGdDRVotOXB6dmRVaVRkWXVoWjJQelFCVE5IbEsxeHhRUUN1MTQ4dXVpVHc4RmtfYnM3ZWZ1R2dVVTd6ZnJLUjJMdmd3NVFMRHBhdkwxMUhuWElLWmloeHpKYmNyakJkS1FDSzBWN3YzaTdGMkNrQSJ9LHsiand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5d2NtbHRZWEo1TFc5eVoyRnVhWHBoZEdsdmJpOTJZV3gxWlM5bVpURXpaakJtWVMweE5tVTFMVFEzWkRZdE9EZGpZeTFoT1RJMU16SmhZemN4WXpRaUxDSnVZVzFsSWpvaVptVXhNMll3Wm1FdE1UWmxOUzAwTjJRMkxUZzNZMk10WVRreU5UTXlZV00zTVdNMElpd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5UQk8yUmJMSUVTTzVoM244Q29wNERWWUpOaEk0Nm5mYUFJdXpVdVRKNzN2NWowbXlwbGNqM2FtTnlXX1BQUnhTYXVNaEc1Z3doa1NyWUhnbk8tZjQyM2E3WW5HVzFTbWZxbXBFRmQ4czVqMXlHUkl5dEpzdWFWRDBCNW5mcmpTa1M0QnU1bFY4SjJwWW1uYW5aa3JfTW82b2oyX0loSVRrMGxWQlRncmktUFRVZkdLTkNGZkNJM2JwRkgyVXdidk56SkQ2d25pVzVDOXJPRzdvQk1TYkRUT0sySEpLXzNtZjFEaWZ6b0gwaVFZMnI1ZnlKem9tdFlEZDJaNEJHdFBuV3BVNndBRjNyY2ZPWXFZRFcxS0E3NFBzUFptMmthcUM3SWNxMVB2cUZnbFgzUXdwbXZRcXBFdnpXU05TM25ORnVpNXlqdXBrSFNsWGZVMjRDRW4zRUEifSx7Imp3dCI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoxY213aU9pSm9kSFJ3Y3pvdkwyRmhMblpwY25SeWRTNWpiMjB2WVhSMGNpOXpkWEJsY2kxaFpHMXBiaTkyWVd4MVpTOTBjblZsSWl3aWJtRnRaU0k2ZEhKMVpTd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5wa3ZBdlJ4VTNwY3FUQ3ZVQ3VKdEN3RWc4VW5Ya0xHS1VnZEg3YUJuSFdxQ2l4X0NYdF9PcUo1VC1iNTh4bHN6ZWx5dmNkbXZUUXh5ZzFfYUhYT0tnNXdEUVFhQTZVcjNOc2JZcjNvc2tyUEk4ZEU4Z0lLMzI2TlBwcXJqcnBCR0dYa1BvSkhrWHdHTzVHZnF0b05wdUZXZDhZNVVETG1IMVFLZWdzQkpRQVZvVjZKcFdHdlB5UF9hcEFMOGNOUE5pVEh1QUwyUnlFMTdBcmh6aUh1NlVqYXFfZmFKYUM4c2doU2VqR2pXNlNwZFdpU0Y5S3cwclY0ZFpXalJzUnU5cWJXZjNnck1JTXFFb1AtM21TbHB4aHBEUFdUUzBoUmFDblN2cG5lUXluRnZoYktNQTJYQTB6MjlaOWk2SnVlUWlzcmpLVkoxUGlhWXZaSVdOenozT0EifV0sInB1YmxpY0tleSI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVPMG54aEdDeXVFYkhPcU5YaldJXG4yZGZ1TkM5ano2SjlaS2IzZHZvc1pMdGlybzMyK2pnZWV1ZGNPMC9sMVArUnpHa09SVUd1YnJrTi9vVVd0QzlsXG5ESmdxM1QwNXBRSlVjZy8rc2J5TDFHdlVuVTBpSmZWazl6ejV3M2NEQkUvSTk5ckNHc0lmRzJtK3VuS0tKbjIyXG53ZC9aT3FRRE93Wk42b0RrQjdaV1FKZTBRQlF1YjBsSmpUaG9nclBWaVhJSnFSZ1RvSCt0c2pVWCtodGtwOFFBXG52dmt3MDlYYzFIWjZraFpWZGZZZjdCbTBZSTBPVkNNYko3N0JWc01HMGNDc0QvOGgzLzI2RjdvcTl1aWFlVG54XG5zWkJzemZCWEpHcFVtNDBuYWFRSi80Q0lxMjBRVGFkclhMTXAxQ1JNblI1VGNlTHZ2L0twR2xRR1hiNFY0elJmXG5xUUlEQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tIiwiYWxpYXNlcyI6W10sImlhdCI6MTU1MzQ4NTI0NywiZXhwIjoxNTUzNTcxNjQ3fQ.mh1ub1kS9WryrLGj3ONFmk6EGl6rPE29VJU21O3IX4EslCkxmIMVVjpFf8s83uFkyy7c2w5Re6NJsln9FHgLTV7RKqdj71U6tE7onh6l8_ZBNPCdetrCcrMCFac65k67_Lz5XM4BVPyCvNuoe-gY8FkeqyimQzkL6Q52HNG2FpslDrgcx50HiCC_aX638UyyB3W4n7J4uF8LrLzsNqyXb2xQw9BVVBJ9-XmXUgOmFaMMG5wJyxFETpP9yR3YBCwiZw911tc5CC738ho4IufdX98HBPqECMIkoL4ZJmfVw4N7YlbaJDU5WZa2rqCpgmvn_B4Zlv1QnVf41fj4EOifyg\",\n"
    //                                      "\n"
    //                                      "    \"publicKey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\\nqQIDAQAB\\n-----END PUBLIC KEY-----\", \n"
    //                                      "    \n"
    //                                      "    \"signerPublicKey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\\nqQIDAQAB\\n-----END PUBLIC KEY-----\", \n"
    //                                      "    \n"
    //                                      "    \"userId\": \"sreddy@virtrudeploy.us\"\n"
    //                                      "}";
    // auto entityObject = EntityObject::createEntityObjectFromJson(entityObjectJsonStr);

    try {
        std::string dummpyKey{"dummy"};
        PolicyObject policyObject;
        policyObject.addDissem(user);
        auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user));
        auto tdf = tdfbuilderPtr->setKasUrl(kasUrl)
                        .enableOIDC(true)
                        .setKasPublicKey(dummpyKey)
                        .setMetaData({{"displayName", "sdk-test.pdf"}})
                        .setHttpHeaders(headers)
                        .setPolicyObject(policyObject)
                        .build();

        BOOST_TEST_MESSAGE("TDF basic test passed.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
        std::cout << "virtru exception " << exception.what() << std::endl;
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_advanced) {
#if ENABLE_TEST
    class ExternalLogger : public ILogger {
      public:
        /// A callback interface for log messages.
        void TDFSDKLog(LogMessage logMessage) override {

            std::ostringstream os;
            std::time_t timeInSeconds = (logMessage.timestamp / 1000);
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

    auto headers = GetHeaders();

    auto policyObject = PolicyObject{};
    policyObject.addDissem(user);

    // Store the uuid for later verification.
    auto policyUuid = policyObject.getUuid();

    auto kasKeys = GetKeypair();
    auto clientKeys = GetKeypair();

    try {
#if TEST_ENCRYPT_DECRYPT
        { // Remote
            std::unordered_map<std::string, std::string> metaData;
            metaData.insert({"displayName", "sdk-test.pdf"});
            metaData.insert({"fileProvider", "tdf-cpp-sdk"});

            std::string mimeType{"application/pdf"};

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user));
            auto tdf = tdfbuilderPtr->setKasUrl(kasUrl)
                            .setKasPublicKey(std::get<0>(kasKeys))
                            .setHttpHeaders(headers)
                            .setExternalLogger(externalLogger, LogLevel::Debug)
                            .setDefaultSegmentSize(2 * 1024 * 1024)
                            .setMetaData(metaData)
                            .setPrivateKey(std::get<1>(clientKeys))
                            .setPublicKey(std::get<0>(clientKeys))
                            .enableOIDC(true)
                            .setEncryptionObject(KeyType::split, CipherType::Aes256GCM)
                            .setIntegrityAlgorithm(IntegrityAlgorithm::HS256, IntegrityAlgorithm::GMAC)
                            .setKeyAccessType(KeyAccessType::Remote)
                            .setHTTPServiceProvider(mockNetwork)
                            .setPayloadMimeType(mimeType)
                            .setPolicyObject(policyObject)
                            .build();

            std::string currentDir = getCurrentWorkingDir();

            // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("\\data\\sample.pdf");

            std::string outPathEncrypt{currentDir};
            outPathEncrypt.append("\\data\\encrypt\\sample.pdf.tdf");

            std::string inPathDecrypt{currentDir};
            inPathDecrypt.append("\\data\\encrypt\\sample.pdf.tdf");

            std::string outPathDecrypt{currentDir};
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

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            tdf->encryptFile(inPathEncrypt, outPathEncrypt);

            //Since the client just encrypted, we expect the mock to have captured
            //an upsert request with the wrapped key - we'll take that out and have
            //the mock return a re-wrapped copy on the next call to `rewrap`
            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

            auto tdfPolicyStr = tdf->getPolicy(ioStream);
            auto policy = nlohmann::json::parse(tdfPolicyStr);
            auto &attributes = policy[kBody][kDissem]

            auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
            BOOST_TEST(attributes.contains(user));
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

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user));
            auto tdf = tdfbuilderPtr->setKasUrl(kasUrl)
                            .setKasPublicKey(std::get<0>(kasKeys))
                            .setHttpHeaders(headers)
                            .setExternalLogger(externalLogger, LogLevel::Debug)
                            .setDefaultSegmentSize(2 * 1024 * 1024)
                            .setPrivateKey(std::get<1>(clientKeys))
                            .setPublicKey(std::get<0>(clientKeys))
                            .enableOIDC(true)
                            .setMetaData(metaData)
                            .setEncryptionObject(KeyType::split, CipherType::Aes256GCM)
                            .setIntegrityAlgorithm(IntegrityAlgorithm::HS256, IntegrityAlgorithm::GMAC)
                            .setKeyAccessType(KeyAccessType::Wrapped)
                            .setHTTPServiceProvider(mockNetwork)
                            .setPolicyObject(policyObject)
                            .build();

            std::string currentDir = getCurrentWorkingDir();

            // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("\\data\\sample.pdf");

            std::string outPathEncrypt{currentDir};
            outPathEncrypt.append("\\data\\encrypt\\sample-wrapped.pdf.tdf");

            std::string inPathDecrypt{currentDir};
            inPathDecrypt.append("\\data\\encrypt\\sample-wrapped.pdf.tdf");

            std::string outPathDecrypt{currentDir};
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

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            tdf->encryptFile(inPathEncrypt, outPathEncrypt);

            auto tdfPolicyUuid = tdf->getPolicyUUID(outPathEncrypt);
            BOOST_TEST(tdfPolicyUuid == policyUuid);

            // Lazy sync the policy.
            tdf->sync(outPathEncrypt);

            //Since the client just encrypted, we expect the mock to have captured
            //an upsert request with the wrapped key - we'll take that out and have
            //the mock return a re-wrapped copy on the next call to `rewrap`
            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation(
                "https://api-develop01.develop.virtru.com/kas/v2/rewrap",
                headers,
                fakeRewrapResp,
                200);

            std::cout << std::endl;

            tdf->decryptFile(inPathDecrypt, outPathDecrypt);
        }
#endif
        BOOST_TEST_MESSAGE("TDF basic test passed.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_html_tdfs) {

#if ENABLE_TEST
    try {

        std::string currentDir = getCurrentWorkingDir();

        auto kasKeys = GetKeypair();
        auto clientKeys = GetKeypair();
        auto headers = GetHeaders();
#if TEST_ENCRYPT_DECRYPT

        {

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);
            tdfBuilder->setPolicyObject(policyObject);

            auto tdf = tdfBuilder->build();

#ifdef _WINDOWS
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("\\data\\sample.pdf");

            std::string outPathEncrypt{currentDir};
            outPathEncrypt.append("\\data\\encrypt\\sample.pdf.html");

            std::string inPathDecrypt{currentDir};
            inPathDecrypt.append("\\data\\encrypt\\sample.pdf.html");

            std::string outPathDecrypt{currentDir};
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

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            tdf->encryptFile(inPathEncrypt, outPathEncrypt);

            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

            auto tdfPolicyUuid = tdf->getPolicyUUID(outPathEncrypt);
            BOOST_TEST(tdfPolicyUuid == policyUuid);

            std::cout << std::endl;

            tdf->decryptFile(inPathDecrypt, outPathDecrypt);
        }

        { // Wrapper with no meta data

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Html, kasKeys, clientKeys);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);
            auto tdf = tdfBuilder->build();

            // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("\\data\\sample.pdf");

            std::string outPathEncrypt{currentDir};
            outPathEncrypt.append("\\data\\encrypt\\sample-wrapped.pdf.html");

            std::string inPathDecrypt{currentDir};
            inPathDecrypt.append("\\data\\encrypt\\sample-wrapped.pdf.html");

            std::string outPathDecrypt{currentDir};
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

            // //Set up a mocked upsert expectation
            // //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            tdf->encryptFile(inPathEncrypt, outPathEncrypt);

            auto tdfPolicyUuid = tdf->getPolicyUUID(outPathEncrypt);
            BOOST_TEST(tdfPolicyUuid == policyUuid);

            // Lazy sync the policy.
            tdf->sync(outPathEncrypt);

            //Since the client just encrypted, we expect the mock to have captured
            //an upsert request with the wrapped key - we'll take that out and have
            //the mock return a re-wrapped copy on the next call to `rewrap`
            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);
            std::cout << std::endl;

            tdf->decryptFile(inPathDecrypt, outPathDecrypt);
        }
#endif
        BOOST_TEST_MESSAGE("TDF basic test passed.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_stream_tdf_type) {

#if ENABLE_TEST
    try {

        auto kasKeys = GetKeypair();
        auto clientKeys = GetKeypair();
        auto headers = GetHeaders();

#if TEST_ENCRYPT_DECRYPT
        { // Remote using tdf to encrypt stream

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Zip, kasKeys, clientKeys);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            auto tdf = tdfBuilder->build();

            // Create simple string.
            std::string plainText{"HelloWorld!!"};
            std::istringstream inputStream(plainText);
            std::stringstream ioStream; // will be used as input and output stream

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

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

                auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
                auto upsertReq = std::get<1>(capturedRequest);

                auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);
                mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

                // decrypt the file
                std::string outTxtFile{"simple.txt"};
                tdf->decryptFile(tdfFile, outTxtFile);

                std::ifstream inputFileStream(outTxtFile);
                std::string decryptedText((std::istreambuf_iterator<char>(inputFileStream)),
                                          std::istreambuf_iterator<char>());
                BOOST_TEST(plainText == decryptedText);
            }

            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

            std::ostringstream decryptedStream;
            tdf->decryptStream(ioStream, decryptedStream);
            std::string decryptedText = decryptedStream.str();

            BOOST_TEST(plainText == decryptedText);
        }

        { // Wrapper with no meta data

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Zip, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            //For these tests there's no `upsert` call to capture for the wrappedKey,
            //so set a POSTTransformer lambda on the mock that will intercept the `rewrap`
            //request inline
            std::function<std::string(std::string &&)> lambda = [kasKeys, clientKeys](std::string &&inBody) {
                return test_tdf_builder_v2_suite::BuildFakedRewrapResponse(inBody, kasKeys, clientKeys);
            };
            mockNetwork->POSTTransformer = lambda;
            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, "", 200);
            tdfBuilder->setHTTPServiceProvider(mockNetwork);

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

#endif
        BOOST_TEST_MESSAGE("TDF streaming test passed using zip format.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_stream_html_type) {
#if ENABLE_TEST
    try {

        auto kasKeys = GetKeypair();
        auto clientKeys = GetKeypair();
        auto headers = GetHeaders();
#if TEST_ENCRYPT_DECRYPT
        { // Remote

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto tdf = tdfBuilder->build();

            // Create simple string.
            std::string plainText{"HelloWorld!!"};
            std::istringstream inputStream(plainText);
            std::stringstream ioStream;

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            // encrypt the stream.
            tdf->encryptStream(inputStream, ioStream);

            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

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

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Html, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            //For 'wrapped' tests there's no `upsert` call to capture for the wrappedKey,
            //so set a POSTTransformer lambda on the mock that will intercept the `rewrap`
            //request inline
            std::function<std::string(std::string &&)> lambda = [kasKeys, clientKeys](std::string &&inBody) {
                return test_tdf_builder_v2_suite::BuildFakedRewrapResponse(inBody, kasKeys, clientKeys);
            };
            mockNetwork->POSTTransformer = lambda;
            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, "", 200);

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
#endif
        BOOST_TEST_MESSAGE("TDF streaming test passed using html format.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_16mb_stream_tdf_type) {
#if ENABLE_TEST
    try {

        auto kasKeys = GetKeypair();
        auto clientKeys = GetKeypair();
        auto headers = GetHeaders();

#if TEST_ENCRYPT_DECRYPT
        { // Remote using tdf to encrypt stream

            std::string currentDir = getCurrentWorkingDir();

            // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("\\data\\sample.pdf");
#else
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("/data/sample.pdf");
#endif

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Zip, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto tdf = tdfBuilder->build();

            // Create a stream for 16mb file.
            std::ifstream inputStream{inPathEncrypt, std::ios_base::out | std::ios_base::binary};
            std::stringstream ioStream; // will be used as input and output stream

            std::string fileContents{std::istreambuf_iterator<char>(inputStream), std::istreambuf_iterator<char>()};

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            // encrypt the stream.
            tdf->encryptStream(inputStream, ioStream);

            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

            auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
            BOOST_TEST(tdfPolicyUuid == policyUuid);

            std::ostringstream decryptedStream;
            tdf->decryptStream(ioStream, decryptedStream);
            std::string decryptedText = decryptedStream.str();

            BOOST_TEST(fileContents == decryptedText);
        }

#endif
        BOOST_TEST_MESSAGE("TDF streaming(16 mb) test passed using zip format.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_16mb_stream_html_type) {
#if ENABLE_TEST
    try {

        auto kasKeys = GetKeypair();
        auto clientKeys = GetKeypair();
        auto headers = GetHeaders();

#if TEST_ENCRYPT_DECRYPT
        { // Remote using tdf to encrypt stream

            std::string currentDir = getCurrentWorkingDir();

            // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("\\data\\sample.pdf");
#else
            std::string inPathEncrypt{currentDir};
            inPathEncrypt.append("/data/sample.pdf");
#endif

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto tdf = tdfBuilder->build();

            // Create a stream for 16mb file.
            std::ifstream inputStream{inPathEncrypt, std::ios_base::out | std::ios_base::binary};
            std::stringstream ioStream; // will be used as input and output stream

            std::string fileContents{std::istreambuf_iterator<char>(inputStream), std::istreambuf_iterator<char>()};

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            // encrypt the stream.
            tdf->encryptStream(inputStream, ioStream);

            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

            auto tdfPolicyUuid = tdf->getPolicyUUID(ioStream);
            BOOST_TEST(tdfPolicyUuid == policyUuid);

            std::ostringstream decryptedStream;
            tdf->decryptStream(ioStream, decryptedStream);
            std::string decryptedText = decryptedStream.str();

            BOOST_TEST(fileContents == decryptedText);
        }

#endif
        BOOST_TEST_MESSAGE("TDF streaming(16 mb) test passed using zip format.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_callback_tdf_type) {
#if ENABLE_TEST
    try {

        auto kasKeys = GetKeypair();
        auto clientKeys = GetKeypair();
        auto headers = GetHeaders();

#if TEST_ENCRYPT_DECRYPT
        { // Remote using tdf to encrypt stream

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Zip, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto tdf = tdfBuilder->build();

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            std::string plainText{"Virtru offers data protection solutions for the most commonly used"
                                  " tools and applications across all industries"};
            std::stringstream ioStream;
            ByteArray<5> buffer;
            SourceAndSinkInterfaceEncrypt(tdf.get(), plainText, &ioStream, &buffer);

            //Since the client just encrypted, we expect the mock to have captured
            //an upsert request with the wrapped key - we'll take that out and have
            //the mock return a re-wrapped copy on the next call to `rewrap`
            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

            SourceAndSinkInterfaceDecrypt(tdf.get(), plainText, &ioStream, &buffer);
        }

        { // Wrapper with no meta data

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Zip, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            std::function<std::string(std::string &&)> lambda = [kasKeys, clientKeys](std::string &&inBody) {
                return test_tdf_builder_v2_suite::BuildFakedRewrapResponse(inBody, kasKeys, clientKeys);
            };
            mockNetwork->POSTTransformer = lambda;
            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, "", 200);

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto tdf = tdfBuilder->build();

            std::string plainText{"Virtru offers data protection solutions for the most commonly used"
                                  " tools and applications across all industries"};
            std::stringstream ioStream;
            ByteArray<5> buffer;
            SourceAndSinkInterfaceEncrypt(tdf.get(), plainText, &ioStream, &buffer);
            SourceAndSinkInterfaceDecrypt(tdf.get(), plainText, &ioStream, &buffer);
        }

#endif
        BOOST_TEST_MESSAGE("TDF streaming test passed using zip format.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_CASE(test_tdf_builder_callback_html_type) {
#if ENABLE_TEST
    try {

        auto kasKeys = GetKeypair();
        auto clientKeys = GetKeypair();
        auto headers = GetHeaders();

#if TEST_ENCRYPT_DECRYPT
        { // Remote

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Remote, Protocol::Html, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            auto tdf = tdfBuilder->build();

            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);

            std::string plainText{"Virtru offers data protection solutions for the most commonly used"
                                  " tools and applications across all industries"};
            std::stringstream ioStream;
            ByteArray<5> buffer;
            SourceAndSinkInterfaceEncrypt(tdf.get(), plainText, &ioStream, &buffer);

            //Since the client just encrypted, we expect the mock to have captured
            //an upsert request with the wrapped key - we'll take that out and have
            //the mock return a re-wrapped copy on the next call to `rewrap`
            auto capturedRequest = mockNetwork->RecordedPOSTCalls[0];
            auto upsertReq = std::get<1>(capturedRequest);

            auto fakeRewrapResp = BuildFakedRewrapResponse(upsertReq, kasKeys, clientKeys);

            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, fakeRewrapResp, 200);

            SourceAndSinkInterfaceDecrypt(tdf.get(), plainText, &ioStream, &buffer);
        }

        { // Wrapper with no meta data

            auto tdfBuilder = createTDFBuilder(LogLevel::Info, KeyAccessType::Wrapped, Protocol::Html, kasKeys, clientKeys);

            auto policyObject = PolicyObject{};
            policyObject.addDissem(user);

            // Store the uuid for later verification.
            auto policyUuid = policyObject.getUuid();

            tdfBuilder->setPolicyObject(policyObject);

            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

            tdfBuilder->setHTTPServiceProvider(mockNetwork);

            std::function<std::string(std::string &&)> lambda = [kasKeys, clientKeys](std::string &&inBody) {
                return test_tdf_builder_v2_suite::BuildFakedRewrapResponse(inBody, kasKeys, clientKeys);
            };
            mockNetwork->POSTTransformer = lambda;
            //Set up a mocked upsert expectation
            //Response is discarded so doesn't matter
            std::string fakeResp = "NO RESPONSE";
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/upsert", headers, fakeResp, 200);
            mockNetwork->addPOSTExpectation("https://api-develop01.develop.virtru.com/kas/v2/rewrap", headers, "", 200);

            auto tdf = tdfBuilder->build();

            std::string plainText{"Virtru offers data protection solutions for the most commonly used"
                                  " tools and applications across all industries"};
            std::stringstream ioStream;
            ByteArray<5> buffer;
            SourceAndSinkInterfaceEncrypt(tdf.get(), plainText, &ioStream, &buffer);
            SourceAndSinkInterfaceDecrypt(tdf.get(), plainText, &ioStream, &buffer);
        }
#endif
        BOOST_TEST_MESSAGE("TDF streaming test passed using html format.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
#endif
}

BOOST_AUTO_TEST_SUITE_END()
