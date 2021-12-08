//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/25.
//  Copyright 2020 Virtru Corporation
//

#define BOOST_TEST_MODULE test_ecc_mode_policy_config_suite

#include <iostream>
#include <fstream>
#include <memory>

#include "tdf_exception.h"
#include "nanotdf/resource_locator.h"
#include "nanotdf/ecc_mode.h"
#include "nanotdf/symmetric_and_payload_config.h"
#include "nanotdf/policy_info.h"
#include "nanotdf.h"
#include "nanotdf_builder.h"

#include <boost/test/included/unit_test.hpp>

using namespace virtru;
using namespace virtru::nanotdf;

BOOST_AUTO_TEST_SUITE(test_ecc_mode_policy_config_suite)

    BOOST_AUTO_TEST_CASE(test_nano_tdf_test_ecc_params) {

        {
            ECCMode mode;
            mode.setECDSABinding(true);
            mode.setEllipticCurve(EllipticCurve::SECP256R1);

            BOOST_TEST(mode.isECDSABindingEnabled());
            BOOST_TEST(mode.getCurveName() == "prime256v1");

            auto modeValue = static_cast<std::uint8_t>(mode.getECCModeAsByte());
            BOOST_TEST(modeValue == 0x80);
        }

        {
            ECCMode mode;
            mode.setECDSABinding(true);
            mode.setEllipticCurve(EllipticCurve::SECP384R1);

            BOOST_TEST(mode.isECDSABindingEnabled());
            BOOST_TEST(mode.getCurveName() == "secp384r1");

            auto modeValue = static_cast<std::uint8_t>(mode.getECCModeAsByte());
            BOOST_TEST(modeValue == 0x81);
        }

        {
            ECCMode mode;
            mode.setECDSABinding(false);
            mode.setEllipticCurve(EllipticCurve::SECP521R1);

            BOOST_TEST(!mode.isECDSABindingEnabled());
            BOOST_TEST(mode.getCurveName() == "secp521r1");

            auto modeValue = static_cast<std::uint8_t>(mode.getECCModeAsByte());
            BOOST_TEST(modeValue == 0x2);
        }

        {
            gsl::byte byte{0x0};
            ECCMode mode{byte};

            BOOST_TEST(!mode.isECDSABindingEnabled());
            BOOST_TEST(mode.getCurveName() == "prime256v1");

            auto modeValue = static_cast<std::uint8_t>(mode.getECCModeAsByte());
            BOOST_TEST(modeValue == 0x0);
        }

        try {
            ECCMode mode;
            mode.setECDSABinding(false);
            mode.setEllipticCurve(EllipticCurve::SECP256K1);

            BOOST_FAIL("We should not get here" );
        } catch ( const Exception& exception) {
            BOOST_TEST_MESSAGE("Expect exception - curve not supported by this sdk");
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Exception should be thrown" );
            std :: cout << "...\n";
        }

        // Unsupported algorithm.
        try {
            gsl::byte byte{0x86};
            ECCMode mode(byte);
            mode.getCurveName();
            BOOST_FAIL("We should not get here" );
        } catch ( const Exception& exception) {
            BOOST_TEST_MESSAGE("Expect exception - curve not supported");
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Exception should be thrown" );
            std :: cout << "...\n";
        }
    }

    BOOST_AUTO_TEST_CASE(test_nano_tdf_symmetric_and_payload_config) {

        {
            SymmetricAndPayloadConfig config;
            config.setHasSignature(false);
            config.setSignatureECCMode(EllipticCurve::SECP256R1);
            config.setSymmetricCipherType(NanoTDFCipher::AES_256_GCM_64_TAG);

            BOOST_TEST(!config.hasSignature());

            if (config.getSignatureECCMode() != EllipticCurve::SECP256R1) {
                BOOST_FAIL("Invalid elliptic curve type.");
            }

            if (config.getCipherType() != NanoTDFCipher::AES_256_GCM_64_TAG) {
                BOOST_FAIL("Invalid symmetric cipher type.");
            }

            auto modeValue = static_cast<std::uint8_t>(config.getSymmetricAndPayloadConfigAsByte());
            BOOST_TEST(modeValue == 0x0);
        }

        {
            SymmetricAndPayloadConfig config;
            config.setHasSignature(true);
            config.setSignatureECCMode(EllipticCurve::SECP384R1);
            config.setSymmetricCipherType(NanoTDFCipher::AES_256_GCM_104_TAG);

            BOOST_TEST(config.hasSignature());

            if (config.getSignatureECCMode() != EllipticCurve::SECP384R1) {
                BOOST_FAIL("Invalid elliptic curve type.");
            }

            if (config.getCipherType() != NanoTDFCipher::AES_256_GCM_104_TAG) {
                BOOST_FAIL("Invalid symmetric cipher type.");
            }

            auto modeValue = static_cast<std::uint8_t>(config.getSymmetricAndPayloadConfigAsByte());
            BOOST_TEST(modeValue == 0x92);
        }

        {
            SymmetricAndPayloadConfig config;
            config.setHasSignature(true);
            config.setSignatureECCMode(EllipticCurve::SECP521R1);
            config.setSymmetricCipherType(NanoTDFCipher::EAD_AES_256_HMAC_SHA_256);

            BOOST_TEST(config.hasSignature());

            if (config.getSignatureECCMode() != EllipticCurve::SECP521R1) {
                BOOST_FAIL("Invalid elliptic curve type.");
            }

            if (config.getCipherType() != NanoTDFCipher::EAD_AES_256_HMAC_SHA_256) {
                BOOST_FAIL("Invalid symmetric cipher type.");
            }

            auto modeValue = static_cast<std::uint8_t>(config.getSymmetricAndPayloadConfigAsByte());
            BOOST_TEST(modeValue == 0xA6);
        }

        {
            SymmetricAndPayloadConfig config;
            config.setHasSignature(false);
            config.setSignatureECCMode(EllipticCurve::SECP256R1);
            config.setSymmetricCipherType(NanoTDFCipher::AES_256_GCM_120_TAG);

            BOOST_TEST(config.hasSignature() == false);

            if (config.getSignatureECCMode() != EllipticCurve::SECP256R1) {
                BOOST_FAIL("Invalid elliptic curve type.");
            }

            if (config.getCipherType() != NanoTDFCipher::AES_256_GCM_120_TAG) {
                BOOST_FAIL("Invalid symmetric cipher type.");
            }

            auto modeValue = static_cast<std::uint8_t>(config.getSymmetricAndPayloadConfigAsByte());
            BOOST_TEST(modeValue == 0x4);
        }

        {
            gsl::byte byte{131};
            SymmetricAndPayloadConfig config{byte};

            BOOST_TEST(config.hasSignature());

            if (config.getSignatureECCMode() != EllipticCurve::SECP256R1) {
                BOOST_FAIL("Invalid elliptic curve type.");
            }

            if (config.getCipherType() != NanoTDFCipher::AES_256_GCM_112_TAG) {
                BOOST_FAIL("Invalid symmetric cipher type.");
            }

            auto modeValue = static_cast<std::uint8_t>(config.getSymmetricAndPayloadConfigAsByte());
            BOOST_TEST(modeValue == 0x83);
        }

        // Unsupported algorithm.
        try {
            gsl::byte byte{15};
            SymmetricAndPayloadConfig config{byte};
            BOOST_FAIL("We should not get here" );
        } catch ( const Exception& exception) {
            BOOST_TEST_MESSAGE("Expect exception - symmetric cipher not supported");
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Exception should be thrown" );
            std :: cout << "...\n";
        }
    }

BOOST_AUTO_TEST_SUITE_END()