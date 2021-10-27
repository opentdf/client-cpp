//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/07.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_rsa_key_pair

#include "rsa_key_pair.h"
#include "crypto_utils.h"

#include <string>
#include <iostream>
#include <time.h>

#include <boost/test/included/unit_test.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>

BOOST_AUTO_TEST_SUITE(test_rsa_key_pair_suite)

namespace vc = virtru::crypto;
struct BioDeleter { void operator()(BIO* bio) {::BIO_free(bio);} };
struct RsaDeleter {	void operator()(RSA* rsa) {	::RSA_free(rsa); }	};

BOOST_AUTO_TEST_CASE(rsa_key_pair_2048)
{
    auto keyPairOf2048 = vc::RsaKeyPair::Generate(2048);
    auto privateKey = keyPairOf2048->PrivateKeyInPEMFormat();
    auto publicKey = keyPairOf2048->PublicKeyInPEMFormat();

    std::unique_ptr<BIO, BioDeleter> privateKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> privateRSA { PEM_read_bio_RSAPrivateKey(privateKeyBuffer.get(),
            nullptr, nullptr, nullptr) };

    std::unique_ptr<BIO, BioDeleter> publicKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> publicRSA { PEM_read_bio_RSAPrivateKey(publicKeyBuffer.get(), nullptr,
            nullptr, nullptr) };

    BOOST_TEST(RSA_size(privateRSA.get()) == 256, "Checking RSA private key length - key size 256 bytes");
    BOOST_TEST(RSA_size(publicRSA.get()) == 256, "Checking RSA public key length - key size 256 bytes");
}

BOOST_AUTO_TEST_CASE(rsa_key_pair_4096)
{
    auto keyPairOf4096 = vc::RsaKeyPair::Generate(4096);
    auto privateKey = keyPairOf4096->PrivateKeyInPEMFormat();
    auto publicKey = keyPairOf4096->PublicKeyInPEMFormat();

    std::unique_ptr<BIO, BioDeleter> privateKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> privateRSA { PEM_read_bio_RSAPrivateKey(privateKeyBuffer.get(),
            nullptr, nullptr, nullptr) };

    std::unique_ptr<BIO, BioDeleter> publicKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> publicRSA { PEM_read_bio_RSAPrivateKey(publicKeyBuffer.get(),
            nullptr, nullptr, nullptr) };

    BOOST_TEST(RSA_size(privateRSA.get()) == 512, "Checking RSA private key length - key size 512 bytes");
    BOOST_TEST(RSA_size(publicRSA.get()) == 512, "Checking RSA public key length - key size 512 bytes");
}

BOOST_AUTO_TEST_CASE(rsa_key_pair_negative_test)
{
    try {
        auto desginedToFailkeyPair = vc::RsaKeyPair::Generate(-1);
        auto privateKey = desginedToFailkeyPair->PrivateKeyInPEMFormat();
        auto publicKey = desginedToFailkeyPair->PublicKeyInPEMFormat();
        BOOST_FAIL("We should not get here" );
    } catch ( const vc::CryptoException& exception) {
        BOOST_TEST_MESSAGE("Expect crypto exception");
        std :: cout << exception.what() << std::endl;
    } catch ( ... ) {
        BOOST_FAIL("Crypto exception should be thrown" );
        std :: cout << "...\n";
    }
}

BOOST_AUTO_TEST_SUITE_END()