/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/16
//

#include "tdf_exception.h"
#include "gcm_decryption.h"

namespace virtru::crypto {

    /// Constructor
    GCMDecryption::GCMDecryption(EVP_CIPHER_CTX_free_ptr ctx) : m_ctx { std::move(ctx) } {
    }

    /// Creates an instance of GCMDecryption.
    std::unique_ptr<GCMDecryption> GCMDecryption::create(Bytes key, Bytes iv) {

        // Create and initialise the context.
        EVP_CIPHER_CTX_free_ptr ctx { EVP_CIPHER_CTX_new () };

        // Initialise the encryption operation.
        auto rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        if (1 != rc) {
            ThrowOpensslException("EVP_aes_256_gcm initialization failed.");
        }

        // Set the IV length
        rc = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        if (1 != rc) {
            ThrowOpensslException("IV length initialization failed.");
        }

        // Initialise key and IV
        rc = EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, toUchar(key.data()), toUchar(iv.data()));
        if (1 != rc) {
            ThrowOpensslException("Key and IV initialization failed.");
        }

        return std::unique_ptr<GCMDecryption>(new GCMDecryption(std::move(ctx)));
    }

    /// Creates an instance of GCMDecryption.
    std::unique_ptr<GCMDecryption> GCMDecryption::create(Bytes key, Bytes iv, Bytes aad) {
        // Create and initialise the context.
        EVP_CIPHER_CTX_free_ptr ctx { EVP_CIPHER_CTX_new () };

        // Initialise the encryption operation.
        auto rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        if (1 != rc) {
            ThrowOpensslException("EVP_aes_256_gcm initialization failed.");
        }

        // Set the IV length
        rc = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        if (1 != rc) {
            ThrowOpensslException("IV length initialization failed.");
        }

        // Initialise key and IV
        rc = EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, toUchar(key.data()), toUchar(iv.data()));
        if (1 != rc) {
            ThrowOpensslException("Key and IV initialization failed.");
        }

        int len;
        rc = EVP_DecryptUpdate(ctx.get(), nullptr, &len, toUchar(aad.data()), aad.size());

        if (1 != rc) {
            ThrowOpensslException("AAD initialization failed.");
        }

        return std::unique_ptr<GCMDecryption>(new GCMDecryption(std::move(ctx)));
    }


    /// Performs decryption of the given data.
    void GCMDecryption::decrypt(Bytes encryptedData, WriteableBytes& decryptedData) {

        if (encryptedData.size() > std::numeric_limits<int>::max()) {
            ThrowException("CBC encoding input buffer is too big");
        }

        auto decryptedDataSize = 0;
        const auto final = finalizeSize (decryptedData, decryptedDataSize);

        if(decryptedData.size() < encryptedData.size() + margin()) {
            ThrowException("Input buffer is bigger than output buffer.");
        }

        const auto rc = EVP_DecryptUpdate(m_ctx.get(),
                                          toUchar(decryptedData.data()),
                                          &decryptedDataSize,
                                          toUchar(encryptedData.data()),
                                          encryptedData.size());

        if (1 != rc) {
            ThrowOpensslException("Block decryption(aes-256-gcm) failed.");
        }
    }

    /// Writes additional authenticated data for modes for the given tag.
    void GCMDecryption::finish(WriteableBytes& tag) {

        auto rc = EVP_CIPHER_CTX_ctrl(m_ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(),
                                      const_cast<gsl::byte *> (tag.data()));
        if (1 != rc) {
            ThrowOpensslException("Gcm get tag failed.");
        }

        auto decryptedDataSize = 0;
        rc = EVP_DecryptFinal_ex(m_ctx.get(), nullptr, &decryptedDataSize);
        if (1 != rc) {
            ThrowOpensslException("Final block decryption(aes-256-gcm) failed.");
        }
    }
}  // namespace virtru::crypto
