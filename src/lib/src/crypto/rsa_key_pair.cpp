/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/02.
//

#include "rsa_key_pair.h"
#include "crypto_utils.h"

#include <iostream>

#include <type_traits>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

namespace virtru::crypto {

    RsaKeyPair::RsaKeyPair(RSA_free_ptr rsa) : m_rsa(std::move(rsa)) {}

    std::string RsaKeyPair::PublicKeyInPEMFormat() const {
        BIO_free_ptr bio{BIO_new(BIO_s_mem())};

        if (1 != PEM_write_bio_RSA_PUBKEY(bio.get(), m_rsa.get())) {
            ThrowOpensslException("Failed to retrieve public key data.");
        }

        // Read the public key from the buffer and put it in the string
        std::string publicKeyPem(BIO_pending(bio.get()), '\0');
        auto readResult = BIO_read(bio.get(), publicKeyPem.data(), static_cast<int>(publicKeyPem.size()));
        if (readResult <= 0) {
            ThrowOpensslException("Failed to read public key data.");
        }

        return publicKeyPem;
    }

    std::string RsaKeyPair::PrivateKeyInPEMFormat() const {
        BIO_free_ptr bio{BIO_new(BIO_s_mem())};

        if (1 != PEM_write_bio_RSAPrivateKey(bio.get(), m_rsa.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
            ThrowOpensslException("Failed to retrieve private key data.");
        }

        // Read the private key from the buffer and put it in the string
        std::string privateKeyPem(BIO_pending(bio.get()), '\0');
        auto readResult = BIO_read(bio.get(), privateKeyPem.data(), static_cast<int>(privateKeyPem.size()));
        if (readResult <= 0) {
            ThrowOpensslException("Failed to read private key data.");
        }

        return privateKeyPem;
    }

    std::unique_ptr<RsaKeyPair> RsaKeyPair::Generate(unsigned keySize) {

        RSA_free_ptr rsa{RSA_new()};
        BIGNUM_free_ptr bne{BN_new()};

        // TODO: use Logger
        if (1 != BN_set_word(bne.get(), RSA_F4)) {
            ThrowOpensslException("Failed exponent generation.");
        }

        if (1 != RSA_generate_key_ex(rsa.get(), static_cast<int>(keySize), bne.get(), nullptr)) {
            ThrowOpensslException("Failed RsaKeyPair generation.");
        }

        return std::unique_ptr<RsaKeyPair>(new RsaKeyPair(std::move(rsa)));
    }
}  // namespace virtru::crypto
