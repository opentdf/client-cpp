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

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <boost/scope_exit.hpp>

#include "crypto_utils.h"
#include "tdf_exception.h"
#include "asym_decryption.h"

namespace virtru::crypto {

    /// Constructor
    AsymDecryption::AsymDecryption(EVP_PKEY_free_ptr privateKey, size_t keySize)
    : m_privateKey(std::move(privateKey)), m_rsaSize {keySize} { }

    /// Creates an instance of AsymDecryption.
    std::unique_ptr<AsymDecryption> AsymDecryption::create(const std::string& privateKey) {
        EVP_PKEY_free_ptr privateKeyPtr;
        BIO_free_ptr privateKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };

        if (!privateKeyBuffer) {
            ThrowOpensslException("Failed to allocate memory for private key.");
        }

        // Store the private key into RSA struct
        privateKeyPtr.reset(PEM_read_bio_PrivateKey(privateKeyBuffer.get(), nullptr, nullptr, nullptr));
        if (!privateKeyPtr) {
            ThrowOpensslException("Failed to create a private key.");
        }

        size_t keySize = EVP_PKEY_bits(privateKeyPtr.get());
        return std::unique_ptr<AsymDecryption>(new AsymDecryption(std::move(privateKeyPtr), keySize));
    }

    /// Performs decryption of the given data.
    void AsymDecryption::decrypt(Bytes encryptedData, WriteableBytes& decryptedData) const {

        if (encryptedData.size() > std::numeric_limits<int>::max()) {
            ThrowException("Asymmetric decoding input buffer is too big");
        }

        size_t size = 0;
        BOOST_SCOPE_EXIT(&size, &decryptedData) {
            size_t min = 0;
            decryptedData = decryptedData.first(std::max(min, size));
        }
        BOOST_SCOPE_EXIT_END

        if (static_cast<size_t>(decryptedData.size()) < m_rsaSize) {
            ThrowException("Asymmetric decoding output buffer is too small");
        }

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new(m_privateKey.get(), NULL)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        auto ret = EVP_PKEY_decrypt_init(evpPkeyCtxPtr.get());
        if (ret <= 0) {
            ThrowOpensslException("Failed to initialize decryption process.");
        }

        ret = EVP_PKEY_CTX_set_rsa_padding(evpPkeyCtxPtr.get(), static_cast<int>(m_padding));
        if (ret <= 0) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

       ret = EVP_PKEY_decrypt(evpPkeyCtxPtr.get(), nullptr,
                              &size,
                              toUchar(encryptedData.data()),
                              static_cast<int>(encryptedData.size()));
        if (ret <= 0) {
            ThrowOpensslException("Failed to calaculate the length of decrypt buffer EVP_PKEY_decrypt.");
        }

        size_t outBufferSize = decryptedData.size();
        if (outBufferSize < size) {
            ThrowException("Decrypt out buffer too small.");
        }

        ret = EVP_PKEY_decrypt(evpPkeyCtxPtr.get(),
                               toUchar(decryptedData.data()),
                               &size,
                               toUchar(encryptedData.data()),
                               static_cast<int>(encryptedData.size()));
        if (ret <= 0) {
            ThrowOpensslException("Decryption failed using asymmetric decoding.");
        }
    }

    /// Returns minimal buffer size required for output.
    size_t AsymDecryption::getOutBufferSize() const noexcept {
        return m_rsaSize;
    }
}  // namespace virtru::crypto
