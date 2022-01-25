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

#include "crypto_utils.h"
#include "tdf_exception.h"
#include "asym_decryption.h"

namespace virtru::crypto {

    /// Constructor
    AsymDecryption::AsymDecryption(RSA_free_ptr privateKey, size_t keySize)
    : m_privateKey(std::move(privateKey)), m_rsaSize {keySize} { }

    /// Creates an instance of AsymDecryption.
    std::unique_ptr<AsymDecryption> AsymDecryption::create(const std::string& privateKey) {
        RSA_free_ptr privateKeyPtr;
        BIO_free_ptr privateKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };

        if (!privateKeyBuffer) {
            ThrowOpensslException("Failed to allocate memory for private key.");
        }

        // Store the private key into RSA struct
        privateKeyPtr.reset(PEM_read_bio_RSAPrivateKey(privateKeyBuffer.get(), nullptr, nullptr, nullptr));
        if (!privateKeyPtr) {
            ThrowOpensslException("Failed to create a private key.");
        }

        size_t keySize = RSA_size(privateKeyPtr.get());
        return std::unique_ptr<AsymDecryption>(new AsymDecryption(std::move(privateKeyPtr), keySize));
    }

    /// Performs decryption of the given data.
    void AsymDecryption::decrypt(Bytes encryptedData, WriteableBytes& decryptedData) const {

        if (encryptedData.size() > std::numeric_limits<int>::max()) {
            ThrowException("Asymmetric decoding input buffer is too big");
        }

        auto size = 0;
        BOOST_SCOPE_EXIT(&size, &decryptedData) {
            decryptedData = decryptedData.first(std::max(0, size));
        }
        BOOST_SCOPE_EXIT_END

        if (static_cast<size_t>(decryptedData.size()) < m_rsaSize) {
            ThrowException("Asymmetric decoding output buffer is too small");
        }

        size = RSA_private_decrypt(static_cast<int>(encryptedData.size()),
                                   toUchar(encryptedData.data()),
                                   toUchar(decryptedData.data()),
                                   m_privateKey.get(),
                                   static_cast<int>(m_padding));
        if (-1 == size) {
            ThrowOpensslException("Decryption failed using asymmetric decoding.");
        }
    }

    /// Returns minimal buffer size required for output.
    size_t AsymDecryption::getOutBufferSize() const noexcept {
        return m_rsaSize;
    }
}  // namespace virtru::crypto
