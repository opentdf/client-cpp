/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/10.
//

#ifndef VIRTRU_ASYM_ENCRYPTION_H
#define VIRTRU_ASYM_ENCRYPTION_H

#include "openssl_deleters.h"
#include "bytes.h"

#include <string>
#include <memory>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace virtru::crypto {

    ///
    /// Provides asymmetric encoding/encryption of the payload. Assume the consumer of this
    /// class to pass the RSA public key to encrypt and use 'AsymDecoding' class to decrypt
    /// the payload by passing RSA private key.
    ///

    /// Reference of the OpenSSL API - https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html

    class AsymEncryption {
    public: // Interface

        /// Supported padding
        enum class Padding {
            kRsaPkcs1Padding = RSA_PKCS1_PADDING,
            kRsaNoPadding = RSA_NO_PADDING,
            kRsaPkcs1OaepPadding = RSA_PKCS1_OAEP_PADDING // Recommended and default
        };

        /// Creates an instance of AsymEncryption.
        /// \param publicKey - A string which contains encryption key in PEM format.
        /// \param padding - A supported padding value.
        /// \return Unique ptr of the instance.
        static std::unique_ptr<AsymEncryption> create(const std::string& publicKey);

        /// Performs encryption of the given data.
        /// \param data - A buffer which contains data to be encrypted
        /// \param encryptedData - A buffer for encrypted data output
        void encrypt(Bytes data, WriteableBytes& encryptedData) const;

        /// Returns minimal buffer size required for output.
        /// \return - The size_t, the minimal buffer size required for output.
        size_t getOutBufferSize() const noexcept ;

        // Not supported.
        AsymEncryption(const AsymEncryption &) = delete;
        AsymEncryption(AsymEncryption &&) = delete;
        AsymEncryption & operator=(const AsymEncryption &) = delete;
        AsymEncryption & operator=(AsymEncryption &&) = delete;
        
    public: // Helper method
        /// Return public key in PEM format.
        /// \return string - In PEM format.
        std::string pemFormat() const;

    private:
        /// Constructor
        explicit AsymEncryption(EVP_PKEY_free_ptr publicKey, size_t keySize);

        // Data
        EVP_PKEY_free_ptr m_publicKey;
        size_t m_rsaSize;
        Padding m_padding {Padding::kRsaPkcs1OaepPadding};
    };
}  // namespace virtru::crypto

#endif //VIRTRU_ASYM_ENCRYPTION_H
