/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/10.
//

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <boost/scope_exit.hpp>
#include <boost/algorithm/string.hpp>

#include <openssl/err.h>
#include <openssl/x509.h>

#include "crypto_utils.h"
#include "tdf_exception.h"
#include "asym_encryption.h"

namespace virtru::crypto {

    constexpr auto kX509CertTag = "BEGIN CERTIFICATE";

    /// Constructor
    AsymEncryption::AsymEncryption(RSA_free_ptr publicKey, size_t keySize)
    : m_publicKey(std::move(publicKey)), m_rsaSize {keySize} { }

    /// Creates an instance of AsymEncryption.
    std::unique_ptr<AsymEncryption> AsymEncryption::create(const std::string& publicKey) {
        RSA_free_ptr publicKeyPtr;
        BIO_free_ptr publicKeyBuffer { BIO_new_mem_buf(publicKey.data(), publicKey.size()) };

        if (!publicKeyBuffer) {
            ThrowOpensslException("Failed to allocate memory for public key.");
        }

        if (boost::contains(publicKey, kX509CertTag)) {

            X509_free_ptr x509Ptr{ PEM_read_bio_X509(publicKeyBuffer.get(), NULL, NULL, NULL) };
            if (!x509Ptr) {
                ThrowOpensslException("Failed to create X509 cert struct.");
            }
            
            EVP_PKEY_free_ptr evppkeyPtr { X509_get_pubkey(x509Ptr.get()) };
            if (!evppkeyPtr) {
                ThrowOpensslException("Failed to create EVP_PKEY.");
            }

            // Store the public key into RSA struct
            publicKeyPtr.reset(EVP_PKEY_get1_RSA(evppkeyPtr.get()));
            
        } else {
            // Store the public key into RSA struct
            publicKeyPtr.reset(PEM_read_bio_RSA_PUBKEY(publicKeyBuffer.get(), nullptr, nullptr, nullptr));
        }

        if (!publicKeyPtr) {
            ThrowOpensslException("Failed to create a public key.");
        }

        size_t keySize = RSA_size(publicKeyPtr.get());
        return std::unique_ptr<AsymEncryption>(new AsymEncryption(std::move(publicKeyPtr), keySize));
    }

    /// Performs encryption of the given data.
    void AsymEncryption::encrypt(Bytes data, WriteableBytes& encryptedData) const {

        if (data.size() > std::numeric_limits<int>::max()) {
            ThrowException("Asymmetric encoding input buffer is too big");
        }

        auto size = 0;
        BOOST_SCOPE_EXIT(&size, &encryptedData) {
            encryptedData = encryptedData.first(std::max(0, size));
        }
        BOOST_SCOPE_EXIT_END

        if (static_cast<size_t>(encryptedData.size()) < m_rsaSize) {
            ThrowException("Asymmetric encoding output buffer is too small");
        }

        // NOTE: from https://www.openssl.org/docs/man1.1.1/man3/RSA_public_encrypt.html
        // flen(data size) must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes,
        // less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa) for RSA_NO_PADDING .
        if ((Padding::kRsaPkcs1Padding == m_padding) &&
            static_cast<size_t>(data.size()) >= m_rsaSize - 11) {
            ThrowException("Input buffer is too big for provided key.");
        } else if (Padding::kRsaPkcs1OaepPadding == m_padding && static_cast<size_t>(data.size()) >= m_rsaSize - 41) {
            ThrowException("Input buffer is too big for provided key.");
        }

        size = RSA_public_encrypt(static_cast<int>(data.size()),
                                  toUchar(data.data()),
                                  toUchar(encryptedData.data()),
                                  m_publicKey.get(),
                                  static_cast<int>(m_padding));
        if (-1 == size) {
            ThrowOpensslException("Encryption failed using asymmetric encoding.");
        }
    }


    /// Returns minimal buffer size required for output.
    size_t AsymEncryption::getOutBufferSize() const noexcept {
        return m_rsaSize;
    }
    
    /// Return public key in PEM format.
    std::string AsymEncryption::pemFormat() const {
        BIO_free_ptr bio{BIO_new(BIO_s_mem())};

        if (1 != PEM_write_bio_RSA_PUBKEY(bio.get(), m_publicKey.get())) {
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
}  // namespace virtru::crypto

