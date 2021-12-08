//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/08.
//  Copyright 2020 Virtru Corporation
//

#define BOOST_TEST_MODULE test_nano_tdf_header_suite

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
#include "nanotdf/header.h"
#include "sdk_constants.h"
#include "crypto/crypto_utils.h"

#include <boost/test/included/unit_test.hpp>

using namespace virtru;
using namespace virtru::crypto;
using namespace virtru::nanotdf;

void testHeader(std::string& kasUrl, ECCMode& eccMode, SymmetricAndPayloadConfig payloadConfig) {

    static constexpr auto kGmacPayloadLength = 8;
    static auto policy = R"policy({"body":{"dataAttributes":[],"dissem":["cn=virtru-user","user@example.com"]},
"uuid":"1a84b9c7-d59c-45ed-b092-c7ed7de73a07"})policy"s;

    // Some buffers for compare.
    std::vector<gsl::byte> compressedPubKey;
    std::vector<gsl::byte> headerBuffer;
    std::vector<gsl::byte> encryptedPayLoad;
    std::vector<gsl::byte> policyBinding;
    std::vector<gsl::byte> encryptKey;

    auto tagSize = SymmetricAndPayloadConfig::SizeOfAuthTagForCipher(payloadConfig.getCipherType());
    std::vector<gsl::byte> tag(tagSize);

    auto sdkECKeyPair = ECKeyPair::Generate(eccMode.getCurveName());
    auto sdkPrivateKeyForEncrypt = sdkECKeyPair->PrivateKeyInPEMFormat();
    auto sdkPublicKeyForEncrypt = sdkECKeyPair->PublicKeyInPEMFormat();

    auto kasECKeyPair = ECKeyPair::Generate(eccMode.getCurveName());
    auto kasPublicKey = kasECKeyPair->PublicKeyInPEMFormat();


    { // Encrypt
        Header header{};

        ResourceLocator kasLocator{kasUrl};
        header.setKasLocator(std::move(kasLocator));

        header.setECCMode(eccMode);
        header.setPayloadConfig(payloadConfig);

        auto secret = ECKeyPair::ComputeECDHKey(kasPublicKey, sdkPrivateKeyForEncrypt);
        std::array<std::uint8_t, 6u> saltValue = {'V', 'I', 'R', 'T', 'R', 'U'};
        auto salt = calculateSHA256(toBytes(saltValue));
        encryptKey = ECKeyPair::calculateHKDF(toBytes(salt), toBytes(secret));

        // -----------------------------------------------------------------
        // Encrypt the policy with key from KDF
        // -----------------------------------------------------------------
        auto encryptedPayLoadSize = policy.size() + kNanoTDFIvSize + tagSize;
        encryptedPayLoad.resize(encryptedPayLoadSize);
        {
            auto encryptedData = toWriteableBytes(encryptedPayLoad);
            ByteArray<kNanoTDFIvSize> iv = symmetricKey<kNanoTDFIvSize>();

            // Adjust the span to add the IV vector at the start of the buffer
            auto encryptBufferSpan = encryptedData.subspan(kNanoTDFIvSize);

            auto encoder = GCMEncryption::create(toBytes(encryptKey), iv);
            encoder->encrypt(toBytes(policy), encryptBufferSpan);

            auto authTag = WriteableBytes{tag};
            encoder->finish(authTag);

            // Copy IV at start
            std::copy(iv.begin(), iv.end(), encryptedData.begin());

            // Copy tag at end
            std::copy(tag.begin(), tag.end(), encryptedData.begin() + kNanoTDFIvSize + policy.size());
        }

        // Create a encrypted policy.
        PolicyInfo encryptedPolicy;
        encryptedPolicy.setEmbeddedEncryptedTextPolicy(toBytes(encryptedPayLoad));

        auto digest = calculateSHA256(toBytes(encryptedPayLoad));
        if (eccMode.isECDSABindingEnabled()) {
            // Calculate the ecdsa binding.
            policyBinding = ECKeyPair::ComputeECDSASig(toBytes(digest), sdkPrivateKeyForEncrypt);
            encryptedPolicy.setPolicyBinding(toBytes(policyBinding));
        } else {
            // Calculate the gmac binding
            auto gmac = toBytes(digest).last(kGmacPayloadLength);
            encryptedPolicy.setPolicyBinding(toBytes(gmac));
        }

        header.setPolicyInfo(std::move(encryptedPolicy));

        compressedPubKey = ECKeyPair::CompressedECPublicKey(sdkPublicKeyForEncrypt);
        header.setEphemeralKey(toBytes(compressedPubKey));

        auto headerSize = header.getTotalSize();
        headerBuffer.resize(headerSize);
        auto sizeWritten = header.writeIntoBuffer(toWriteableBytes(headerBuffer));
        BOOST_TEST(sizeWritten == headerSize);
    }

    { // Decrypt
        Header header{toBytes(headerBuffer)};

        // Test kas locator in header.
        ResourceLocator kasLocator = header.getKasLocator();
        BOOST_TEST(kasLocator.getResourceUrl() == kasUrl);

        // Test ECCMode in header.
        ECCMode decryptECCMode = header.getECCMode();
        if (decryptECCMode.getEllipticCurveType() != eccMode.getEllipticCurveType()) {
            BOOST_FAIL("Curve type not matched.");
        }
        BOOST_TEST(decryptECCMode.isECDSABindingEnabled() == eccMode.isECDSABindingEnabled());

        // Test SymmetricAndPayloadConfig in header
        SymmetricAndPayloadConfig config = header.getPayloadConfig();
        if (config.getCipherType() != payloadConfig.getCipherType()) {
            BOOST_FAIL("Cipher type not matched.");
        }
        BOOST_TEST(config.hasSignature() == payloadConfig.hasSignature());

        // Test PolicyInfo in header.
        PolicyInfo policyInfo = header.getPolicyInfo();
        if (policyInfo.getPolicyType() != NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED) {
            BOOST_FAIL("Policy type should be of EMBEDDED_POLICY_ENCRYPTED.");
        }

        auto encryptedPolicy = policyInfo.getEmbeddedEncryptedTextPolicy();

        // -----------------------------------------------------------------
        // Decrypt the policy with key from KDF
        // -----------------------------------------------------------------
        std::string decryptedPolicy;
        decryptedPolicy.resize(encryptedPolicy.size() - kNanoTDFIvSize - tagSize);
        {
            // Copy the auth tag from the data buffer.
            std::copy_n(encryptedPolicy.last(tagSize).data(), tagSize, begin(tag));

            // Update the input buffer size after the auth tag is copied.
            auto inputSpan = encryptedPolicy.first(encryptedPolicy.size() - tagSize);
            auto decoder = GCMDecryption::create(toBytes(encryptKey), inputSpan.first(kNanoTDFIvSize));

            // Update the input buffer size after the IV is copied.
            inputSpan = inputSpan.subspan(kNanoTDFIvSize);

            // decrypt
            auto decryptedData = toWriteableBytes(decryptedPolicy);
            decoder->decrypt(inputSpan, decryptedData);

            auto authTag = WriteableBytes{tag};
            decoder->finish(authTag);
        }
        BOOST_TEST(decryptedPolicy == policy);

        auto binding = policyInfo.getPolicyBinding();
        auto digest = calculateSHA256(encryptedPolicy);
        if (decryptECCMode.isECDSABindingEnabled()) {
            auto result = ECKeyPair::VerifyECDSASignature(toBytes(digest), toBytes(binding),
                    sdkPublicKeyForEncrypt);

            BOOST_TEST(result);
        } else {
            // Calculate the gmac binding
            auto gmac = toBytes(digest).last(kGmacPayloadLength);

            std::vector<gsl::byte> actualBinding(binding.size());
            std::copy(binding.begin(), binding.end(), actualBinding.begin());

            std::vector<gsl::byte> actualGmac(gmac.size());
            std::copy(gmac.begin(), gmac.end(), actualGmac.begin());

            for (size_t index = 0; index < actualGmac.size(); ++index) {
                if (actualGmac[index] != actualBinding[index]) {
                    BOOST_FAIL("GMAC binding is not valid.");
                }
            }
        }
    }

}

BOOST_AUTO_TEST_SUITE(test_nano_tdf_header)

    std::array<std::uint8_t, 8u> binding = {0x33, 0x31, 0x63, 0x31, 0x66, 0x35, 0x35, 0x00};
    const std::string remotePolicyUrl = "https://api-develop01.develop.virtru.com/acm/api/policies/1a1d5e42-bf91-45c7-a86a-61d5331c1f55"s;

    // Curve - "prime256v1"
    const auto sdkPrivateKey = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1HjFYV8D16BQszNW
6Hx/JxTE53oqk5/bWaIj4qV5tOyhRANCAAQW1Hsq0tzxN6ObuXqV+JoJN0f78Em/
PpJXUV02Y6Ex3WlxK/Oaebj8ATsbfaPaxrhyCWB3nc3w/W6+lySlLPn5
-----END PRIVATE KEY-----)"s;

    const auto sdkPublicKey = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFtR7KtLc8Tejm7l6lfiaCTdH+/BJ
vz6SV1FdNmOhMd1pcSvzmnm4/AE7G32j2sa4cglgd53N8P1uvpckpSz5+Q==
-----END PUBLIC KEY-----)"s;

    const auto kasPrivateKey = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu2Hmm80uUzQB1OfB
PyMhWIyJhPA61v+j0arvcLjTwtqhRANCAASHCLUHY4szFiVV++C9+AFMkEL2gG+O
byN4Hi7Ywl8GMPOAPcQdIeUkoTd9vub9PcuSj23I8/pLVzs23qhefoUf
-----END PRIVATE KEY-----)"s;

    const auto kasPublicKey = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhwi1B2OLMxYlVfvgvfgBTJBC9oBv
jm8jeB4u2MJfBjDzgD3EHSHlJKE3fb7m/T3Lko9tyPP6S1c7Nt6oXn6FHw==
-----END PUBLIC KEY-----)"s;

    const std::array<std::uint8_t, 33> compressedPubKey = {
            0x03, 0x16, 0xd4, 0x7b, 0x2a, 0xd2, 0xdc, 0xf1, 0x37, 0xa3, 0x9b, 0xb9, 0x7a, 0x95, 0xf8, 0x9a,
            0x09, 0x37, 0x47, 0xfb, 0xf0, 0x49, 0xbf, 0x3e, 0x92, 0x57, 0x51, 0x5d, 0x36, 0x63, 0xa1, 0x31,
            0xdd
    };

    std::array<std::uint8_t, 155u> expectedHeader{
        0x4c, 0x31, 0x4c, 0x01, 0x12, 0x61, 0x70, 0x69, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x2e,
        0x63, 0x6f, 0x6d, 0x2f, 0x6b, 0x61, 0x73, 0x00, 0x00, 0x00, 0x01, 0x56, 0x61, 0x70, 0x69, 0x2d,
        0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x30, 0x31, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f,
        0x70, 0x2e, 0x76, 0x69, 0x72, 0x74, 0x72, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x63, 0x6d,
        0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x2f, 0x31, 0x61,
        0x31, 0x64, 0x35, 0x65, 0x34, 0x32, 0x2d, 0x62, 0x66, 0x39, 0x31, 0x2d, 0x34, 0x35, 0x63, 0x37,
        0x2d, 0x61, 0x38, 0x36, 0x61, 0x2d, 0x36, 0x31, 0x64, 0x35, 0x33, 0x33, 0x31, 0x63, 0x31, 0x66,
        0x35, 0x35, 0x33, 0x31, 0x63, 0x31, 0x66, 0x35, 0x35, 0x00, 0x03, 0x16, 0xd4, 0x7b, 0x2a, 0xd2,
        0xdc, 0xf1, 0x37, 0xa3, 0x9b, 0xb9, 0x7a, 0x95, 0xf8, 0x9a, 0x09, 0x37, 0x47, 0xfb, 0xf0, 0x49,
        0xbf, 0x3e, 0x92, 0x57, 0x51, 0x5d, 0x36, 0x63, 0xa1, 0x31, 0xdd
    };

    BOOST_AUTO_TEST_CASE(test_nano_tdf_header_remote_policy) {

        std::array<std::uint8_t, 155u> headerData{};
        { // Construct empty header - encrypt use case
            Header header{};

            ResourceLocator kasLocator{"https://api.exampl.com/kas"};
            header.setKasLocator(std::move(kasLocator));

            ECCMode eccMode{gsl::byte{0x0}}; //no ecdsa binding and 'secp256r1'
            header.setECCMode(std::move(eccMode));

            SymmetricAndPayloadConfig payloadConfig{gsl::byte{0x0}}; // no signature and AES_256_GCM_64_TAG
            header.setPayloadConfig(std::move(payloadConfig));

            PolicyInfo policyInfo;
            policyInfo.setRemotePolicy(remotePolicyUrl);
            policyInfo.setPolicyBinding(toBytes(binding));

            header.setPolicyInfo(std::move(policyInfo));
            header.setEphemeralKey(toBytes(compressedPubKey));

            auto headerSize = header.getTotalSize();
            BOOST_TEST(headerSize == headerData.size());

            headerSize = header.writeIntoBuffer(toWriteableBytes(headerData));
            BOOST_TEST(headerSize == headerData.size());
            BOOST_TEST(headerData == expectedHeader);
        }

        { // Construct header from buffer - decrypt use case

            Header header{toBytes(headerData)};

            auto headerSize = header.getTotalSize();
            BOOST_TEST(headerSize == headerData.size());

            auto eccMode = header.getECCMode();
            BOOST_TEST(!eccMode.isECDSABindingEnabled());
            BOOST_TEST(eccMode.getCurveName() == "prime256v1");

            auto payloadConfig = header.getPayloadConfig();
            BOOST_TEST(!payloadConfig.hasSignature());
            if (payloadConfig.getCipherType() != NanoTDFCipher::AES_256_GCM_64_TAG) {
                BOOST_FAIL("Invalid symmetric cipher type.");
            }

            auto policyInfo = header.getPolicyInfo();
            auto policyUrl = policyInfo.getRemotePolicyUrl();
            BOOST_TEST(policyUrl == remotePolicyUrl);

            std::array<std::uint8_t, 33> ephemeralKey{};
            auto ephemeralKeyBytes = header.getEphemeralKey();
            std::memcpy(ephemeralKey.data(), ephemeralKeyBytes.data(), ephemeralKeyBytes.size());
            BOOST_TEST(ephemeralKey == compressedPubKey);

            // Change the magic number
            try {
                expectedHeader[0] = 0x61; // 'a'
                Header header{toBytes(expectedHeader)};
                BOOST_FAIL("We should not get here" );
            } catch ( const Exception& exception) {
                BOOST_TEST_MESSAGE("Expect exception - Invalid Nano TDF Magic number");
                std :: cout << exception.what() << std::endl;
            } catch ( ... ) {
                BOOST_FAIL("Exception should be thrown" );
                std :: cout << "...\n";
            }

            // Change the version number
            try {
                expectedHeader[2] = 0x1; // Version as 1 instead zero
                Header header{toBytes(expectedHeader)};
                BOOST_FAIL("We should not get here" );
            } catch ( const Exception& exception) {
                BOOST_TEST_MESSAGE("Expect exception - Invalid Nano TDF version");
                std :: cout << exception.what() << std::endl;
            } catch ( ... ) {
                BOOST_FAIL("Exception should be thrown" );
                std :: cout << "...\n";
            }
        }
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_header_encrypted_text_policy_with_ecdsa) {

        {
            std::string kasUrl{"https://api.exampl.com/kas"};
            ECCMode eccMode{gsl::byte{0x80}}; // ecdsa binding and 'secp256r1'
            SymmetricAndPayloadConfig payloadConfig{gsl::byte{0x1}}; // no signature and AES_256_GCM_96_TAG
            testHeader(kasUrl, eccMode, payloadConfig);
        }

        {
            std::string kasUrl{"https://api.example.com/kas"};
            ECCMode eccMode{gsl::byte{0x0}}; // non ecdsa binding and 'secp256r1'
            SymmetricAndPayloadConfig payloadConfig{gsl::byte{0x0}}; // no signature and AES_256_GCM_64_TAG
            testHeader(kasUrl, eccMode, payloadConfig);
        }

        {
            std::string kasUrl{"http://localhost:4000/kas"};
            ECCMode eccMode{gsl::byte{0x81}}; // ecdsa binding and 'secp384r1'
            SymmetricAndPayloadConfig payloadConfig{gsl::byte{0x5}}; // no signature and AES_256_GCM_128_TAG
            testHeader(kasUrl, eccMode, payloadConfig);
        }

        {
            std::string kasUrl{"https://local.virtru.com/kas"};
            ECCMode eccMode{gsl::byte{0x82}}; // ecdsa binding and 'secp521r1'
            SymmetricAndPayloadConfig payloadConfig{gsl::byte{0x2}}; // no signature and AES_256_GCM_104_TAG
            testHeader(kasUrl, eccMode, payloadConfig);
        }

    }

BOOST_AUTO_TEST_SUITE_END()