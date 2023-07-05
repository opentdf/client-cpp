//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/03.
//  Copyright 2020 Virtru Corporation
//

#define BOOST_TEST_MODULE test_nano_tdf_policy_info_suite

#include <iostream>
#include <fstream>
#include <memory>

#include "tdf_exception.h"
#include "policy_object.h"
#include "nanotdf/ecc_mode.h"
#include "nanotdf/policy_info.h"
#include "ec_key_pair.h"
#include "gcm_encryption.h"
#include "gcm_decryption.h"
#include "sdk_constants.h"

#include <boost/test/included/unit_test.hpp>

using namespace virtru;
using namespace virtru::crypto;
using namespace virtru::nanotdf;

BOOST_AUTO_TEST_SUITE(test_nano_tdf_policy_info)

    // Curve - secp384r1
    const auto sdkPrivateKey = "-----BEGIN PRIVATE KEY-----\n"
                         "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAXJtdPQ/Ts0x4oxJjx\n"
                         "j/hfhw8b8Uf+8Srz3/Y1F5iu4AP+eSjjoLvxm3mUVBy6PWKhZANiAATgsV7vt5sf\n"
                         "7n3eqLwstkf7m73c+1V6iMRlOLC/7KSproONwuqcW2Ln82ianHgo58c6B2ZmBPFk\n"
                         "EwgypwFRF+3uOByp0brHEZz+cCZOoPCiKI0LIk2kw/XUZQPptOY/hYU=\n"
                         "-----END PRIVATE KEY-----";

    const auto sdkPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4LFe77ebH+593qi8LLZH+5u93PtVeojE\n"
                        "ZTiwv+ykqa6DjcLqnFti5/Nompx4KOfHOgdmZgTxZBMIMqcBURft7jgcqdG6xxGc\n"
                        "/nAmTqDwoiiNCyJNpMP11GUD6bTmP4WF\n"
                        "-----END PUBLIC KEY-----";

    const auto kasPrivateKey = "-----BEGIN PRIVATE KEY-----\n"
                         "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCyip7wzimVDKTHTsB4\n"
                         "PKWMZycGaGLO4XXhpIWd2V7IsaL4lyw8ERLnYuQtw5Jdr9ShZANiAARpUfk7WzMw\n"
                         "vK96mTPF7GO/gd3bV2bpivTyg2+lQXf9bkc2Y8U9hlwNhpUrOVMCM8fcjIxrSZgp\n"
                         "mONauYTANAYIbOozE6KEaDFUBJU8gS8yswON2sp9ZYuqHIfkwVjrPyY=\n"
                         "-----END PRIVATE KEY-----";

    const auto kasPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaVH5O1szMLyvepkzxexjv4Hd21dm6Yr0\n"
                        "8oNvpUF3/W5HNmPFPYZcDYaVKzlTAjPH3IyMa0mYKZjjWrmEwDQGCGzqMxOihGgx\n"
                        "VASVPIEvMrMDjdrKfWWLqhyH5MFY6z8m\n"
                        "-----END PUBLIC KEY-----";

    BOOST_AUTO_TEST_CASE(test_nano_tdf_policy_info_remote) {

        std::array<std::uint8_t, 97u> expectedPolicyData = {
                0x00, 0x01, 0x56, 0x61, 0x70, 0x69, 0x2d, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x30, 0x31,
                0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x2e, 0x76, 0x69, 0x72, 0x74, 0x72, 0x75, 0x2e,
                0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x63, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x6f, 0x6c, 0x69,
                0x63, 0x69, 0x65, 0x73, 0x2f, 0x31, 0x61, 0x31, 0x64, 0x35, 0x65, 0x34, 0x32, 0x2d, 0x62, 0x66,
                0x39, 0x31, 0x2d, 0x34, 0x35, 0x63, 0x37, 0x2d, 0x61, 0x38, 0x36, 0x61, 0x2d, 0x36, 0x31, 0x64,
                0x35, 0x33, 0x33, 0x31, 0x63, 0x31, 0x66, 0x35, 0x35, 0x33, 0x31, 0x63, 0x31, 0x66, 0x35, 0x35,
                0x00};

        std::array<std::uint8_t, 8u> binding = {0x33, 0x31, 0x63, 0x31, 0x66, 0x35, 0x35, 0x00};
        std::string policyUrl(
                "https://api-develop01.develop.virtru.com/acm/api/policies/1a1d5e42-bf91-45c7-a86a-61d5331c1f55");
        std::array<std::uint8_t, 97u> policyData;

        // Create a empty PolicyInfo object and remote policy(encrypt case) - no ecdsa binding.
        {
            PolicyInfo remotePolicy;
            remotePolicy.setRemotePolicy(policyUrl);

            remotePolicy.setPolicyBinding(toBytes(binding));
            auto totalSize = remotePolicy.getTotalSize();

            BOOST_TEST(policyData.size() == totalSize);
            remotePolicy.writeIntoBuffer(toWriteableBytes(policyData));
            BOOST_TEST(policyData == expectedPolicyData);
            BOOST_TEST(policyUrl == remotePolicy.getRemotePolicyUrl());
        }

        // Create a PolicyInfo object from buffer(decrypt case)
        {
            ECCMode mode{static_cast<gsl::byte>(0x2)}; // no ecdsa binding and 'secp256r1'
            PolicyInfo remotePolicy{toBytes(expectedPolicyData), mode};

            std::array<std::uint8_t, 8u> actualBinding;
            auto bindingBytes = remotePolicy.getPolicyBinding();
            std::memcpy(actualBinding.data(), bindingBytes.data(), bindingBytes.size());

            remotePolicy.writeIntoBuffer(toWriteableBytes(policyData));

            BOOST_TEST(actualBinding == binding);
            BOOST_TEST(expectedPolicyData.size() == remotePolicy.getTotalSize());
            BOOST_TEST(policyUrl == remotePolicy.getRemotePolicyUrl());
            BOOST_TEST(policyData == expectedPolicyData);
        }
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_policy_info_plain_text) {
        std::array<std::uint8_t, 8u> binding = {0x33, 0x31, 0x63, 0x31, 0x66, 0x39, 0x35, 0x90};

        ECCMode mode{static_cast<gsl::byte>(0x2)}; // no ecdsa binding and 'secp256r1'

        auto policyObject = PolicyObject{};
        policyObject.addDissem("cn=virtru-user");
        for (std::size_t index = 0; index < 100; ++index) {
            auto email = "user" + std::to_string(index) + "@example.com";
            policyObject.addDissem(email);
        }

        auto policyAsStr = policyObject.toJsonString();

        PolicyInfo plainTextPolicy;
        plainTextPolicy.setEmbeddedPlainTextPolicy(toBytes(policyAsStr));
        plainTextPolicy.setPolicyBinding(toBytes(binding));

        auto policySize = plainTextPolicy.getTotalSize();
        std::vector<gsl::byte> policyData(policySize);

        auto totalBytesFilled = plainTextPolicy.writeIntoBuffer(toWriteableBytes(policyData));
        BOOST_TEST(policySize == totalBytesFilled);

        PolicyInfo plainTextPolicy2{toBytes(policyData), mode};
        auto policyAsBytes = plainTextPolicy2.getEmbeddedPlainTextPolicy();
        std::string policyAsStr2(reinterpret_cast<const char *>(policyAsBytes.data()),
                                 policyAsBytes.size());

        std::array<std::uint8_t, 8u> actualBinding;
        auto bindingBytes = plainTextPolicy2.getPolicyBinding();
        std::memcpy(actualBinding.data(), bindingBytes.data(), bindingBytes.size());

        BOOST_TEST(policyAsStr == policyAsStr2);
        BOOST_TEST(actualBinding == binding);
        BOOST_TEST(policySize == plainTextPolicy2.getTotalSize());

        {
            auto policy = R"policy({"body":{"dataAttributes":[],"dissem":["cn=virtru-user","user@example.com"]},
                        "uuid":"1a64b8c7-d59d-45ed-b092-c7ed7df76a97"})policy"s;

            std::array<std::uint8_t, 8u> hmacBinding = {
                    0x23, 0x86, 0x4d, 0x70, 0x75, 0xdf, 0x03, 0x75
            };

            PolicyInfo plainTextPolicy;
            plainTextPolicy.setEmbeddedPlainTextPolicy(toBytes(policy));
            plainTextPolicy.setPolicyBinding(toBytes(binding));

            // Calculate the binding
            auto hash = calculateSHA256(toBytes(policy));
            auto gmac = toBytes(hash).last(kNanoTDFGMACLength);
            plainTextPolicy.setPolicyBinding(toBytes(gmac));

            std::array<std::uint8_t, 8u> actualBinding;
            auto bindingBytes = plainTextPolicy.getPolicyBinding();
            std::memcpy(actualBinding.data(), bindingBytes.data(), bindingBytes.size());

            BOOST_TEST(actualBinding == hmacBinding);

            auto policyAsBytes = plainTextPolicy.getEmbeddedPlainTextPolicy();
            std::string policyAsStr(reinterpret_cast<const char *>(policyAsBytes.data()),
                    policyAsBytes.size());
            BOOST_TEST(policyAsStr == policy);
        }
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_policy_info_encrypted_text_with_ecdsa) {

        constexpr auto IvSize = 3;
        constexpr auto AuthTagSize = 8;
        std::array<std::uint8_t, 3u> saltValue = {'T', 'D', 0};
        std::array<std::uint8_t, IvSize> fixedIV = {0x6f, 0xde, 0xcd };

        std::array<std::uint8_t, 32u> sha256Digest = {
                0x93, 0x4a, 0x01, 0x1c, 0x31, 0xc8, 0xa6, 0x32, 0xa9, 0xb5, 0x5d, 0xf5, 0xa9, 0xb9, 0x73, 0xe6,
                0xe4, 0x55, 0x3a, 0xce, 0x37, 0x89, 0x96, 0xb0, 0x3e, 0xc3, 0x58, 0xa1, 0x3b, 0xc2, 0xad, 0x7f
        };

        // Curve - secp384r1
        constexpr auto keySize = 48u;
        std::array<std::uint8_t, keySize> expectedSecret = {
                0xc9, 0x50, 0xee, 0xbb, 0x99, 0x6b, 0xd1, 0x96, 0x30, 0x4e, 0xe6, 0x0e, 0xaa, 0xc8, 0xc8, 0x60,
                0xb2, 0xed, 0x52, 0x51, 0x8f, 0xfd, 0x69, 0x2c, 0x45, 0x07, 0xd3, 0x2e, 0x43, 0xe0, 0x4e, 0xd8,
                0x1a, 0xf1, 0xdc, 0xa9, 0xd5, 0xad, 0x25, 0x70, 0x73, 0x58, 0x26, 0x24, 0xa8, 0x24, 0x58, 0xd3
        };

        std::array<std::uint8_t, keySize> expectedKey = {
                0x3d, 0x68, 0x14, 0x25, 0x61, 0xc2, 0x55, 0x1a, 0x12, 0x3a, 0x25, 0x3c, 0xe3, 0x53, 0xa8, 0xe2,
                0xd2, 0xa3, 0xe9, 0x8b, 0xa5, 0xe8, 0x26, 0x28, 0x9b, 0x9a, 0x0c, 0x6b, 0xfa, 0xf3, 0x72, 0xef,
                0x99, 0x99, 0x7f, 0x09, 0xdc, 0xe8, 0xec, 0x16, 0xd3, 0xf8, 0x3d, 0x4a, 0xd7, 0x1b, 0x75, 0xbe
        };

        auto policy = R"policy({"body":{"dataAttributes":[],"dissem":["cn=virtru-user","user0@example.com",
                        "user1@example.com","user2@example.com","user3@example.com","user4@example.com"]},
                        "uuid":"1a84b9c7-d59c-45ed-b092-c7ed7de73a07"})policy"s;

        ECCMode mode{static_cast<gsl::byte>(0x81)}; // ecdsa binding and 'secp384r1'

        auto secret = ECKeyPair::ComputeECDHKey(kasPublicKey, sdkPrivateKey);
        std::array<std::uint8_t, keySize> secretAsArray{};
        std::memcpy(secretAsArray.data(), secret.data(), secret.size());
        BOOST_TEST(expectedSecret == secretAsArray);

        auto salt = calculateSHA256(toBytes(saltValue));

        auto key = ECKeyPair::calculateHKDF(toBytes(salt), toBytes(secret));
        std::array<std::uint8_t, keySize> keyAsArray{};
        std::memcpy(keyAsArray.data(), key.data(),keySize);
        BOOST_TEST(keyAsArray == expectedKey);

        // -----------------------------------------------------------------
        // Encrypt the policy with key from KDF
        // -----------------------------------------------------------------
        auto encryptedPayLoadSize = policy.size() + IvSize + AuthTagSize;
        std::vector<gsl::byte> encryptedPayLoad(encryptedPayLoadSize);
        {
            auto encryptedData = toWriteableBytes(encryptedPayLoad);

            ByteArray<AuthTagSize> tag;

            // Copy the fixed IV to match the expected binding value.
            ByteArray<IvSize> iv;
            std::memcpy(iv.data(), fixedIV.data(), fixedIV.size());

            const auto bufferSpan = encryptedData;

            auto encryptedDataSize = 0;
            const auto final = finalizeSize(encryptedData, encryptedDataSize);

            // Adjust the span to add the IV vector at the start of the buffer
            auto encryptBufferSpan = bufferSpan.subspan(IvSize);

            auto encoder = GCMEncryption::create(toBytes(key), iv);
            encoder->encrypt(toBytes(policy), encryptBufferSpan);

            auto authTag = WriteableBytes{tag};
            encoder->finish(authTag);

            // Copy IV at start
            std::copy(iv.begin(), iv.end(), encryptedData.begin());

            // Copy tag at end
            std::copy(tag.begin(), tag.end(), encryptedData.begin() + IvSize + policy.size());

            // Final size.
            encryptedDataSize = encryptedPayLoadSize;
        }

        // Calculate the ecdsa signature.
        auto digest = calculateSHA256(toBytes(encryptedPayLoad));
        std::array<std::uint8_t, 32u> actualDigest{};
        std::memcpy(actualDigest.data(), digest.data(), digest.size());
        BOOST_TEST(actualDigest == sha256Digest);

        auto signature = ECKeyPair::ComputeECDSASig(toBytes(digest), sdkPrivateKey);
        BOOST_TEST(signature.size() == ECCMode::GetECDSASignatureStructSize(mode.getEllipticCurveType()));

        PolicyInfo encryptedPolicy;
        encryptedPolicy.setEmbeddedEncryptedTextPolicy(toBytes(encryptedPayLoad));
        encryptedPolicy.setPolicyBinding(toBytes(signature));

        // Create a policy info by writing the policy
        auto policySize = encryptedPolicy.getTotalSize();
        std::vector<gsl::byte> policyData(policySize);

        auto totalBytesFilled = encryptedPolicy.writeIntoBuffer(toWriteableBytes(policyData));
        BOOST_TEST(policySize == totalBytesFilled);

        // Create a policy info by reading the policy info from buffer
        PolicyInfo encryptedPolicy2{toBytes(policyData), mode};
        auto policyAsBytes = encryptedPolicy2.getEmbeddedEncryptedTextPolicy();
        std::vector<gsl::byte> policyData2(policyAsBytes.begin(), policyAsBytes.end());
        auto bindingBytes = encryptedPolicy2.getPolicyBinding();

        auto sdkDecryptECKeyPair = ECKeyPair::Generate(mode.getCurveName());
        auto sdkEncryptPrivateKey = sdkDecryptECKeyPair->PrivateKeyInPEMFormat();

        auto verifySignature = ECKeyPair::VerifyECDSASignature(toBytes(sha256Digest), bindingBytes, sdkPublicKey);

        BOOST_TEST(verifySignature);
        BOOST_TEST(policyData2 == encryptedPayLoad);
        BOOST_TEST(policySize == encryptedPolicy2.getTotalSize());

        secret = ECKeyPair::ComputeECDHKey(sdkPublicKey, kasPrivateKey);
        std::memcpy(secretAsArray.data(), secret.data(), secret.size());
        BOOST_TEST(expectedSecret == secretAsArray);

        key = ECKeyPair::calculateHKDF(toBytes(salt), toBytes(secret));
        std::memcpy(keyAsArray.data(), key.data(),keySize);
        BOOST_TEST(keyAsArray == expectedKey);

        // -----------------------------------------------------------------
        // Decrypt the policy with key from KDF
        // -----------------------------------------------------------------
        std::string decryptedPolicy;
        decryptedPolicy.resize(policyData2.size() - IvSize - AuthTagSize);
        {
            auto data = toBytes(policyData2);

            // Copy the auth tag from the data buffer.
            ByteArray<AuthTagSize> tag;
            std::copy_n(data.last(AuthTagSize).data(), AuthTagSize, begin(tag));

            // Update the input buffer size after the auth tag is copied.
            auto inputSpan = data.first(data.size() - AuthTagSize);
            auto decoder = GCMDecryption::create(toBytes(key), inputSpan.first(IvSize));

            // Update the input buffer size after the IV is copied.
            inputSpan = inputSpan.subspan(IvSize);

            // decrypt
            auto decryptedData = toWriteableBytes(decryptedPolicy);
            decoder->decrypt(inputSpan, decryptedData);

            auto authTag = WriteableBytes{tag};
            decoder->finish(authTag);
        }

        BOOST_TEST(decryptedPolicy == policy);

        auto policyObject = PolicyObject::CreatePolicyObjectFromJson(decryptedPolicy);
        auto dissems = policyObject.getDissems();
        if (dissems.find("cn=virtru-user") == dissems.end()) {
            BOOST_FAIL("virtru-user is missing from dissems.");
        }

        BOOST_TEST(policyObject.getUuid() == "1a84b9c7-d59c-45ed-b092-c7ed7de73a07");
    }

BOOST_AUTO_TEST_SUITE_END()
