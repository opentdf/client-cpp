//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/22
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_splitkey_encryption_suite

#include "key_access.h"
#include "key_access_object.h"
#include "policy_object.h"
#include "tdf_constants.h"
#include "splitkey_encryption.h"
#include "asym_encryption.h"
#include "bytes.h"
#include "crypto_utils.h"
#include "sdk_constants.h"
#include "asym_decryption.h"
#include "gcm_decryption.h"
#include "bytes.h"
#include "tdf_exception.h"
#include "sdk_constants.h"

#include <tao/json.hpp>
#include <boost/test/included/unit_test.hpp>
#include <memory>

BOOST_AUTO_TEST_SUITE(test_splitkey_encryption_suite)

    using namespace virtru;
    using namespace virtru::crypto;
    using namespace std::string_literals;

    const auto kasPublicKeyAsX509 = "-----BEGIN CERTIFICATE-----\n"
                                    "MIID1DCCArygAwIBAgIJAPco6TKljKMRMA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNV\n"
                                    "BAYTAlVTMQswCQYDVQQIDAJOVjENMAsGA1UEBwwEUmVubzEPMA0GA1UECgwGVmly\n"
                                    "dHJ1MQwwCgYDVQQLDANFbmcxFDASBgNVBAMMC2V4YW1wbGUuY29tMR8wHQYJKoZI\n"
                                    "hvcNAQkBFhB1c2VyQGV4YW1wbGUuY29tMB4XDTE5MDQxNjEzNDkxNloXDTI0MDQx\n"
                                    "NDEzNDkxNlowfzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5WMQ0wCwYDVQQHDARS\n"
                                    "ZW5vMQ8wDQYDVQQKDAZWaXJ0cnUxDDAKBgNVBAsMA0VuZzEUMBIGA1UEAwwLZXhh\n"
                                    "bXBsZS5jb20xHzAdBgkqhkiG9w0BCQEWEHVzZXJAZXhhbXBsZS5jb20wggEiMA0G\n"
                                    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrGSqlDXezSgcc+tWR/1LkJK3xk2JN\n"
                                    "eCxG3BcVI5Y7u3PrN8Cf9JEehrHBEbIDn1klMo/P/CG+jAVEd7+PgU9WDAxj59C6\n"
                                    "RAfAdMT4Emxvx2FffefUAbA0/I8lHrEQK2BPyggarjNSkeW3oPxqWqTZtHHj1AJH\n"
                                    "lv+3QZcTxol2Pnjirim0KT43JhxIHlYTdlGt0wzDPoAQlKRC2vV9yhDd/KLhsx3Q\n"
                                    "1UbW3iofZ9pidaIiYmyYIIEb2GZwvISF8CzfDvBjxMaTdbrCbrs1i3qRogyRh8r0\n"
                                    "xmk22qt5rZv59xf5t4s4E5gOX8UvkD8AtlPROMml/HA/PFL6EN429Sb/AgMBAAGj\n"
                                    "UzBRMB0GA1UdDgQWBBR99W23SPqQsdOp6jrXBgDkjaaKPDAfBgNVHSMEGDAWgBR9\n"
                                    "9W23SPqQsdOp6jrXBgDkjaaKPDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\n"
                                    "CwUAA4IBAQBcRXDE4TkMiCvLXO63fiF05x27fmg0ZUEbMQo/lkE4L0iU7EhN+v6+\n"
                                    "saUZc57OGL/JOGvNgol+6BMNAaRnvAub9pFbSY3KgkGbF7QRwisLQrZZ+JUOKPSf\n"
                                    "r3IMNpuMBlr6PN8b9EDxiyxwS0lxP4bbjWBnbOarVTrdL1/jV8OPkcNxAEHjYFac\n"
                                    "hAfuviZO82aaHBgJ13BkF+sxWF251PYu2dh3bGS6hUJi9BnD3d/fjMR5fpD98rj/\n"
                                    "dlX0BQhvkkCJUvXwZjpWwYYby29FMtSaw2fl9OPTrhceqmF4MfQO4hTAc/X91QOi\n"
                                    "nfNeYqBVj/7rB7QgK7Y6f4hpcq2QYr+g\n"
                                    "-----END CERTIFICATE-----\n"s;

    const auto privateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n"
                               "MIIEowIBAAKCAQEAqxkqpQ13s0oHHPrVkf9S5CSt8ZNiTXgsRtwXFSOWO7tz6zfA\n"
                               "n/SRHoaxwRGyA59ZJTKPz/whvowFRHe/j4FPVgwMY+fQukQHwHTE+BJsb8dhX33n\n"
                               "1AGwNPyPJR6xECtgT8oIGq4zUpHlt6D8alqk2bRx49QCR5b/t0GXE8aJdj544q4p\n"
                               "tCk+NyYcSB5WE3ZRrdMMwz6AEJSkQtr1fcoQ3fyi4bMd0NVG1t4qH2faYnWiImJs\n"
                               "mCCBG9hmcLyEhfAs3w7wY8TGk3W6wm67NYt6kaIMkYfK9MZpNtqrea2b+fcX+beL\n"
                               "OBOYDl/FL5A/ALZT0TjJpfxwPzxS+hDeNvUm/wIDAQABAoIBACw3DLYqjMxgTQZI\n"
                               "K/jWqm0arXjIRZcPfyGwrqZf0+sLviEC/1xWr0ncNQNXt1EIVNkv/8oXtgCv3oyb\n"
                               "BX3oRMBPzMPknCQGgJpTkrMoz6zzMU6kEszOwuJuge9txwQOsYztALskWU71NRAH\n"
                               "IjO5yPAZmXTuzMgDVYHeCVSq8csEXbg72FKG+XsyVZRETw+DEeBTdo5RRz++eHiF\n"
                               "UVfNgLyky1yHHiAA9LeOceq5FoYumOAQXnjCdZ+4vW2i+pFvgPIRQcccC9fjDzRC\n"
                               "ZtqYFnVgOgGVBiJb3VX/G7Cn+872TmwI6WOf/Me/OW3I0l7FCDizeCKbMvPVtHFr\n"
                               "9CpZm4ECgYEA1Xa6y15XKkKL45X6Ds3kOnDZ3BOCs3cJf42NVe3mcO5vaXsLVqVh\n"
                               "S1vrFtL/611kFvJcqtS33dj+e0NCTEIMwrL1Fz/NoVoh3kaH/wUtIxcHwAzIPRaM\n"
                               "zyk8Ibn/DXqfjIAmxNleXO7aVnNvLeQqGfpJwz/Hwg1orgwXxd5TbskCgYEAzTFH\n"
                               "KWTybOyQSzf6Y0TQGtCLCywrNW1Rs0uGywSZnCeT4AROIcGoJqSfAnjcfMGDtkHm\n"
                               "lIUeK/7Lc11bn1kj1QwFt2WKRHv5bCd4hk0qNO62HwXpZhfBZ/Y2oyWRGqqZ+P+P\n"
                               "ubmflD/eaow1YUqhKU6YMAbdppdGCTC31OUuY4cCgYBa+OCerzQCpJ2tfks1Z/Wu\n"
                               "Gk4ehoobJc38eD0Vs++TjWoZ0ACDCrQuQ5wq+/1pN0HiraNkgodhmorJyV5F1ZhO\n"
                               "manuIJjn/NuWOQTYYEJeRABfjpL/xc54syAXV4clHW9Fl4/uMJ0QihKu6T8mlaiD\n"
                               "rbEl7taZEtHb6vduslNoUQKBgA3xLDmmz0YRaNiDjDLUiSNZSilPLfxqWiPJnPYM\n"
                               "cPeIRObyw/BNPUSq6Nb9KVYcu/tVTPqIdP1eSaqkDEaugt3F/Flyv8tZdSAhKnJN\n"
                               "qfGAysUe3LYAJTcQJrQ9KDfcoaumibh/4VTsZgttTW835+1rlrGktcjM/IhBVCxW\n"
                               "CinfAoGBAKHqNWH54K9NDcPX7WXY72oIDNxyL2Nxd/46HToEEgjozyx+S+3yaGLU\n"
                               "L7k/q6jabt+mDbRUgC+6BurOBZSZiE29KGKNyUbWI0LAuNyfktn/spDZbpdLxxLl\n"
                               "v6Ndz6hfZyVNOolxvvdjoMH5i9+1h1POnRzTiTJS9tVGuJhw61Q3\n"
                               "-----END RSA PRIVATE KEY-----\n"s;


    constexpr auto kasUrl = "api.virtru.com";
    const std::string metaData = R"({"displayName" : "effective-c++.pdf"})";
    constexpr auto user1 = "user1@example.com";
    constexpr auto user2 = "user2@example.com";

    BOOST_AUTO_TEST_CASE(test_splitkey_encryption) {

        // Create a Policy;
        auto policyObject = PolicyObject{};
        policyObject.addDissem(user1);
        policyObject.addDissem(user2);

        // Create a split key
        auto splitKey =  SplitKey{CipherType::Aes256GCM};
        
        // Create
        auto keyAccess = std::unique_ptr<KeyAccess>{std::make_unique<WrappedKeyAccess>(kasUrl, kasPublicKeyAsX509,
                                                                                       policyObject, metaData)};
        splitKey.addKeyAccess(std::move(keyAccess));

        // Supports only one key access for now.
        keyAccess = std::unique_ptr<KeyAccess>{std::make_unique<WrappedKeyAccess>(kasUrl, kasPublicKeyAsX509,
                                                                                  policyObject, metaData)};
        BOOST_CHECK_THROW(splitKey.addKeyAccess(std::move(keyAccess)), Exception);

        auto manifest = to_string(splitKey.getManifest());
        std::cout << "Manifest:" << manifest << std::endl;

        tao::json::value manifestJson = tao::json::from_string(manifest);
        auto keyAccessObject = KeyAccessObject::createKeyAccessObjectFromJson(to_string(manifestJson[kKeyAccess][0]));

        std::cout << "WrappedKey:" << keyAccessObject.getWrappedKey() << std::endl;
        auto decodedWrappedKey = base64Decode(keyAccessObject.getWrappedKey());

        // Test if the wrapped key matches after decryption - asymetric.
        auto decoder = AsymDecryption::create(privateKeyPem);
        std::vector<gsl::byte> outBuffer(decoder->getOutBufferSize());
        auto outputBufferSpan = WriteableBytes {outBuffer};
        decoder->decrypt(toBytes(decodedWrappedKey), outputBufferSpan);

        auto wrappedKeyAsHex = hex(toBytes(splitKey.getWrappedKey()));
        BOOST_TEST(wrappedKeyAsHex == hex(outputBufferSpan));

        ///
        // Test if the meta data matches after decryption - symmetric.
        auto encryptedMetadata = base64Decode(keyAccessObject.getEncryptedMetadata());
        tao::json::value metadataObj = tao::json::from_string(encryptedMetadata);
        auto cipherText = base64Decode(metadataObj.as<std::string>(kCiphertext));
        auto binaryIV = base64Decode(metadataObj.as<std::string>(kIV));
        BOOST_CHECK(binaryIV.size() == kGcmIvSize);

        // Copy the auth tag from the cipherText.
        ByteArray<kAesBlockSize> tag;
        auto inputSpan = toBytes(cipherText);
        std::copy_n(inputSpan.last(kAesBlockSize).data(), kAesBlockSize, begin(tag));

        // Update the input buffer size after the auth tag is copied.
        inputSpan = inputSpan.first(inputSpan.size() - kAesBlockSize);
        auto symDecoder = GCMDecryption::create(splitKey.getWrappedKey(), inputSpan.first(kGcmIvSize));

        std::vector<gsl::byte> buffer(cipherText.size());
        auto outBufferSpan = WriteableBytes{buffer};

        // Update the input buffer size after the IV is copied.
        inputSpan = inputSpan.subspan(kGcmIvSize);

        // decrypt
        symDecoder->decrypt(inputSpan, outBufferSpan);

        auto authTag = WriteableBytes{ toWriteableBytes(tag) };
        symDecoder->finish(authTag);

        std::string decryptedMessage(reinterpret_cast<const char *>(&outBufferSpan[0]), outBufferSpan.length());
        BOOST_TEST(metaData == decryptedMessage);
        std::cout << "decryptedMessage:" << decryptedMessage << std::endl;
    }

BOOST_AUTO_TEST_SUITE_END()
