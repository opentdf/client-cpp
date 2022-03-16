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

#ifndef VIRTRU_ASYM_DECRYPTION_H
#define VIRTRU_ASYM_DECRYPTION_H

#include "openssl_deleters.h"
#include "bytes.h"

#include <string>
#include <memory>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace virtru::crypto {

    ///
    /// Provides asymmetric decryption of the payload. Assume the consumer of this
    /// class to pass the RSA private key to encrypt and use 'AsymEncoding' class to decrypt
    /// the payload by passing RSA public key.
    ///

    /// Reference of the OpenSSL API - https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html

    class AsymDecryption {
    public: // Interface

        /// Supported padding
        enum class Padding {
            kRsaPkcs1Padding = RSA_PKCS1_PADDING,
            kRsaNoPadding = RSA_NO_PADDING,
            kRsaPkcs1OaepPadding = RSA_PKCS1_OAEP_PADDING // Recommended and default
        };

        /// Creates an instance of AsymDecryption.
        /// \param privateKey - A string which contains decryption key in PEM format.
        /// \param padding - A supported padding value.
        /// \return Unique ptr of the instance.
        static std::unique_ptr<AsymDecryption> create(const std::string& privateKey);

        /// Performs decryption of the given data.
        /// \param encryptedData - A buffer which contains encrypted data to be decrypted.
        /// \param decryptedData - A buffer for decrypted data output
        void decrypt(Bytes encryptedData, WriteableBytes& decryptedData) const;

        /// Returns minimal buffer size required for output.
        /// \return - The size_t, the minimal buffer size required for output.
        size_t getOutBufferSize() const noexcept ;

        // Not supported.
        AsymDecryption(const AsymDecryption &) = delete;
        AsymDecryption(AsymDecryption &&) = delete;
        AsymDecryption & operator=(const AsymDecryption &) = delete;
        AsymDecryption & operator=(AsymDecryption &&) = delete;

    private:
        /// Constructor
        explicit AsymDecryption(RSA_free_ptr privateKey, size_t keySize);

        // Data
        RSA_free_ptr m_privateKey;
        size_t m_rsaSize;
        Padding m_padding {Padding::kRsaPkcs1OaepPadding};
    };
}  // namespace virtru::crypto

#endif //VIRTRU_ASYM_DECRYPTION_H
