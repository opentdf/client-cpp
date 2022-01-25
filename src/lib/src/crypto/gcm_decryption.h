/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/16
//

#ifndef VIRTRU_GCM_DECRYPTION_H
#define VIRTRU_GCM_DECRYPTION_H

#include "openssl_deleters.h"
#include "crypto_utils.h"

namespace virtru::crypto {

    /// Symmetric aes-256-gcm decryption implementation with streaming support.
    class GCMDecryption {
    public:
        /// Creates an instance of GCMDecryption.
        /// \param key - A byte array which contains decryption key
        /// \param iv - A byte array which contains initialization vector
        /// \return Unique ptr of the instance, ready to use decoder
        static std::unique_ptr<GCMDecryption> create(Bytes key, Bytes iv);

        /// Creates an instance of GCMDecryption.
        /// \param key - A byte array which contains decryption key
        /// \param iv - A byte array which contains initialization vector
        /// \param aad - A byte array of arbitrary size which contains additional authenticated data
        /// \return ready to use decoder
        static std::unique_ptr<GCMDecryption> create(Bytes key, Bytes iv, Bytes aad);

        /// Performs decryption of the given data.
        /// \param encryptedData - A buffer which contains data to be decrypted
        /// \param decryptedData - A buffer for decrypted data output
        void decrypt(Bytes encryptedData, WriteableBytes& decryptedData);

        /// Writes additional authenticated data for modes for the given tag.
        /// \param tag a byte array which contains generated tag
        void finish(WriteableBytes& tag);

        // Not supported.
        GCMDecryption() = delete;
        GCMDecryption(const GCMDecryption &) = delete;
        GCMDecryption(GCMDecryption &&) = delete;
        GCMDecryption & operator=(const GCMDecryption &) = delete;
        GCMDecryption & operator=(GCMDecryption &&) = delete;

    private:

        /// Constructor
        explicit GCMDecryption(EVP_CIPHER_CTX_free_ptr ctx);

        inline int margin() const { return (EVP_CIPHER_CTX_block_size(m_ctx.get())  - 1); }

        /// Data
        EVP_CIPHER_CTX_free_ptr m_ctx;
    };
}  // namespace virtru::crypto

#endif //VIRTRU_GCM_DECRYPTION_H
