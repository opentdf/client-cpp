/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/02.
//

#include "rsa_key_pair.h"
#include "crypto_utils.h"
#include "tdf_exception.h"
#include "sdk_constants.h"

#include <iostream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <boost/scope_exit.hpp>
#include <boost/algorithm/string.hpp>

#include <type_traits>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

namespace virtru::crypto {

    constexpr auto BetterRSAKeySize = 3072;

    RsaKeyPair::RsaKeyPair(EVP_PKEY_free_ptr rsa) : m_rsa(std::move(rsa)) {}

    std::string RsaKeyPair::PublicKeyInPEMFormat() const {
        BIO_free_ptr bio{BIO_new(BIO_s_mem())};

        if (1 != PEM_write_bio_PUBKEY(bio.get(), m_rsa.get())) {
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

        if (1 != PEM_write_bio_PrivateKey(bio.get(), m_rsa.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
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
        EVP_PKEY_free_ptr rsa { EVP_RSA_gen(keySize)};
        if (!rsa) {
            ThrowOpensslException("Failed RsaKeyPair generation.");
        }

        return std::unique_ptr<RsaKeyPair>(new RsaKeyPair(std::move(rsa)));
    }


    /// Compute RSA signature for the digest for the private key.
    std::vector<gsl::byte> RsaKeyPair::ComputeRSASig(Bytes digest,
                                                     const std::string& privateKeyInPEM) {

        if (privateKeyInPEM.empty()) {
            ThrowException("Invalid data to compute the signature.");
        }

        BIO_free_ptr preBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(preBio.get(), privateKeyInPEM.data(), privateKeyInPEM.size()) != privateKeyInPEM.size()) {
            ThrowOpensslException("Failed to load private key.");
        }

        EVP_PKEY_free_ptr rsaKey {PEM_read_bio_PrivateKey(preBio.get(), nullptr, nullptr, nullptr)};
        if (!rsaKey) {
            ThrowOpensslException("Failed to read ec private key from pem format");
        }

        size_t keySize = EVP_PKEY_bits(rsaKey.get());
        if (keySize < BetterRSAKeySize) {
            LogWarn("RSA key is less than 3k");
        }

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new(rsaKey.get(), nullptr)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        if (1 != EVP_PKEY_private_check(evpPkeyCtxPtr.get())) {
            ThrowOpensslException("Failed the sanity check for ec private key");
        }

        if (EVP_PKEY_sign_init(evpPkeyCtxPtr.get()) <= 0) {
            ThrowOpensslException("Failed to rsa context for signing");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(evpPkeyCtxPtr.get(), RSA_PKCS1_PADDING) <= 0) {
            ThrowOpensslException("Failed to set rsa padding");
        }

        if (EVP_PKEY_CTX_set_signature_md(evpPkeyCtxPtr.get(), EVP_sha256()) <= 0) {
            ThrowOpensslException("Failed to set rsa signature");
        }

        size_t sigLength = EVP_PKEY_get_size(rsaKey.get());
        std::vector<gsl::byte> signature(sigLength);

        // Determine buffer length
        if (EVP_PKEY_sign(evpPkeyCtxPtr.get(), nullptr, &sigLength,
                          reinterpret_cast<const uint8_t*>(digest.data()), digest.size()) <= 0) {
            ThrowOpensslException("Failed to calculate length of rsa signature");
        }

        signature.resize(sigLength);
        if (EVP_PKEY_sign(evpPkeyCtxPtr.get(), reinterpret_cast<uint8_t*>(signature.data()),
                          &sigLength,
                          reinterpret_cast<const uint8_t*>(digest.data()), digest.size()) <= 0) {
            ThrowOpensslException("Failed to sign using rsa");
        }

        return signature;
    }

    /// Verify the signature for the digest for the public-key.
    bool RsaKeyPair::VerifyERSASignature(Bytes digest,
                                         Bytes signature,
                                         const std::string& publicKeyInPEM) {
        EVP_PKEY_free_ptr publicKeyPtr;

        BIO_free_ptr publicKeyBuffer { BIO_new_mem_buf(publicKeyInPEM.data(), publicKeyInPEM.size()) };

        if (!publicKeyBuffer) {
            ThrowOpensslException("Failed to allocate memory for public key.");
        }

        if (boost::contains(publicKeyInPEM, kX509CertTag)) {

            X509_free_ptr x509Ptr{ PEM_read_bio_X509(publicKeyBuffer.get(),
                                                     nullptr,
                                                     nullptr,
                                                     nullptr) };
            if (!x509Ptr) {
                ThrowOpensslException("Failed to create X509 cert struct.");
            }

            // Store the public key into EVP_PKEY
            publicKeyPtr.reset(X509_get_pubkey(x509Ptr.get()));

        } else {
            // Store the public key into RSA struct
            publicKeyPtr.reset(PEM_read_bio_PUBKEY(publicKeyBuffer.get(), nullptr, nullptr, nullptr));
        }

        if (!publicKeyPtr) {
            ThrowOpensslException("Failed to create a public key.");
        }

        size_t keySize = EVP_PKEY_bits(publicKeyPtr.get());
        if (keySize < BetterRSAKeySize) {
            LogWarn("RSA key is less than 3k");
        }

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new(publicKeyPtr.get(), nullptr)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        if (EVP_PKEY_verify_init(evpPkeyCtxPtr.get()) <= 0) {
            ThrowOpensslException("Failed to create EVP_PKEY_verify_init");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(evpPkeyCtxPtr.get(), RSA_PKCS1_PADDING) <= 0) {
            ThrowOpensslException("Failed to set rsa padding");
        }

        if (EVP_PKEY_CTX_set_signature_md(evpPkeyCtxPtr.get(), EVP_sha256()) <= 0) {
            ThrowOpensslException("Failed the set rsa signature");
        }

        bool ret = EVP_PKEY_verify(evpPkeyCtxPtr.get(),
                                   reinterpret_cast<const uint8_t*>(signature.data()),
                                   signature.size(),
                                   reinterpret_cast<const uint8_t*>(digest.data()),
                                   digest.size());

        return (ret == 1);
    }

}  // namespace virtru::crypto
