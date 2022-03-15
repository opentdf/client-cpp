/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/15.
//


#include "tdf_exception.h"
#include "gcm_encryption.h"

namespace virtru::crypto {

    /// Constructor
    GCMEncryption::GCMEncryption(EVP_CIPHER_CTX_free_ptr ctx) : m_ctx { std::move(ctx) } {
    }

    /// Creates an instance of GCMEncryption.
    std::unique_ptr<GCMEncryption> GCMEncryption::create(Bytes key, Bytes iv) {

        // Create and initialise the context.
        EVP_CIPHER_CTX_free_ptr ctx { EVP_CIPHER_CTX_new () };

        // Initialise the encryption operation.
        auto rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        if (1 != rc) {
            ThrowOpensslException("EVP_aes_256_gcm initialization failed.");
        }

        // Set the IV length
        rc = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        if (1 != rc) {
            ThrowOpensslException("IV length initialization failed.");
        }

        // Initialise key and IV
        rc = EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, toUchar(key.data()), toUchar(iv.data()));
        if (1 != rc) {
            ThrowOpensslException("Key and IV initialization failed.");
        }

        return std::unique_ptr<GCMEncryption>(new GCMEncryption(std::move(ctx)));
    }

    /// Creates an instance of GCMEncryption.
    std::unique_ptr<GCMEncryption> GCMEncryption::create(Bytes key, Bytes iv, Bytes aad) {
        // Create and initialise the context.
        EVP_CIPHER_CTX_free_ptr ctx { EVP_CIPHER_CTX_new () };

        // Initialise the encryption operation.
        auto rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        if (1 != rc) {
            ThrowOpensslException("EVP_aes_256_gcm initialization failed.");
        }

        // Set the IV length
        rc = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        if (1 != rc) {
            ThrowOpensslException("IV length initialization failed.");
        }

        // Initialise key and IV
        rc = EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, toUchar(key.data()), toUchar(iv.data()));
        if (1 != rc) {
            ThrowOpensslException("Key and IV initialization failed.");
        }

        int len;
        rc = EVP_EncryptUpdate(ctx.get(), nullptr, &len, toUchar(aad.data()), aad.size());

        if (1 != rc) {
            ThrowOpensslException("AAD initialization failed.");
        }

        return std::unique_ptr<GCMEncryption>(new GCMEncryption(std::move(ctx)));
    }


    /// Performs encryption of the given data.
    void GCMEncryption::encrypt(Bytes data, WriteableBytes& encryptedData) {

        if (data.size() > std::numeric_limits<int>::max()) {
            ThrowException("CBC encoding input buffer is too big");
        }

        auto encryptedDataSize = 0;
        const auto final = finalizeSize(encryptedData, encryptedDataSize);

        if(encryptedData.size() < data.size() + margin()) {
            ThrowException("Input buffer is bigger than output buffer.");
        }

        const auto rc = EVP_EncryptUpdate(m_ctx.get(),
                                          toUchar(encryptedData.data()),
                                          &encryptedDataSize,
                                          toUchar(data.data()),
                                          data.size());

        if (1 != rc) {
            ThrowOpensslException("Block encryption(aes-256-gcm) failed.");
        }
    }

    /// Writes additional authenticated data for modes with block size 1
    void GCMEncryption::finish(WriteableBytes& tag) {

        int encryptedDataSize = 0;
        auto rc = EVP_EncryptFinal_ex(m_ctx.get(), nullptr, &encryptedDataSize);
        if (1 != rc) {
            ThrowOpensslException("Final block encryption(aes-256-gcm) failed.");
        }

        rc = EVP_CIPHER_CTX_ctrl(m_ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data());
        if (1 != rc) {
            ThrowOpensslException("Gcm get tag failed.");
        }
    }
}  // namespace virtru::crypto
