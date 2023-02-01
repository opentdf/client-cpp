/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/15
//

#ifndef VIRTRU_GCM_ENCRYPTION_H
#define VIRTRU_GCM_ENCRYPTION_H

#include "openssl_deleters.h"
#include "crypto_utils.h"

namespace virtru::crypto {

    /// Symmetric aes-256-gcm encryption implementation with streaming support.
    class GCMEncryption {
    public:
        /// Creates an instance of GCMEncryption.
        /// \param key - A byte array which contains encryption key
        /// \param iv - A byte array which contains initialization vector
        /// \return Unique ptr of the instance, ready to use encoder
        static std::unique_ptr<GCMEncryption> create(Bytes key, Bytes iv);

        /// Creates an instance of GCMEncryption.
        /// \param key - A byte array which contains encryption key
        /// \param iv - A byte array which contains initialization vector
        /// \param aad - A byte array of arbitrary size which contains additional authenticated data
        /// \return ready to use encoder
        static std::unique_ptr<GCMEncryption> create(Bytes key, Bytes iv, Bytes aad);

        /// Performs encryption of the given data.
        /// \param data - A buffer which contains data to be encrypted
        /// \param encryptedData - A buffer for encrypted data output
        void encrypt(Bytes data, WriteableBytes& encryptedData);

        /// Writes additional authenticated data for modes with block size 1
        /// \param tag a byte array which contains generated tag
        void finish(WriteableBytes& tag);

        // Not supported.
        GCMEncryption() = delete;
        GCMEncryption(const GCMEncryption &) = delete;
        GCMEncryption(GCMEncryption &&) = delete;
        GCMEncryption & operator=(const GCMEncryption &) = delete;
        GCMEncryption & operator=(GCMEncryption &&) = delete;

    private:

        /// Constructor
        explicit GCMEncryption(EVP_CIPHER_CTX_free_ptr ctx);

        inline int margin() const { return (EVP_CIPHER_CTX_block_size(m_ctx.get())  - 1); }

        /// Data
        EVP_CIPHER_CTX_free_ptr m_ctx;
    };
}  // namespace virtru::crypto

#endif //VIRTRU_GCM_ENCRYPTION_H
