/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/04.
//

#ifndef VIRTRU_CRYPTO_UTILS_H
#define VIRTRU_CRYPTO_UTILS_H

#include "logger.h"
#include "bytes.h"

#include <string>
#include <stdexcept>
#include <type_traits>

#include <type_traits>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>


namespace virtru::crypto {

    /// macro for open ssl exception
    #define ThrowOpensslException(message)  virtru::crypto::_ThrowOpensslException(message, __SOURCE_FILENAME__, __LINE__)

    /// Calculate Sha256 of the given buffer and return the hash in hex format. On error OpensslException is thrown.
    /// \param data - The data buffer.
    /// \return - Return 256-bit (32-byte) hash hex value.
    /// NOTE: These hash functions take raw pointer instead of c++ objects because we want to
    /// achieve performance of less than 10 milliseconds when the buffer size of 2MB.
    /// Don't want to waste time calling new/copy constructors on std::string objects.
    std::string hexHashSha256(Bytes data);

    /// Calculate Sha256 of the given buffer and return the hash in binary format. On error OpensslException is thrown.
    /// \param data - The data buffer.
    /// \return - Return 256-bit value.
    /// NOTE: These hash functions take raw pointer instead of c++ objects because we want to
    /// achieve performance of less than 10 milliseconds when the buffer size of 2MB.
    /// Don't want to waste time calling new/copy constructors on std::string objects.
    std::array<gsl::byte, 32u> calculateSHA256(Bytes data);

    /// Convert the binary data to Hex format.
    /// \param data - The data buffer.
    /// \return - Return the hex string.
    std::string hex(Bytes data);

    /// Create an HMAC  of the given data and return the hash in hex format. On error OpensslException is thrown.
    /// \param toSignData - The data that needs to signed.
    /// \param secret - The secret which used by HMAC algorithm .
    /// \return - Return 256-bit (32-byte) hmac hash hex value.
    std::string hexHmacSha256(Bytes toSignData, Bytes secret);

    /// Create an HMAC  of the given data and return the hash in binary format. On error OpensslException is thrown.
    /// \param toSignData - The data that needs to signed.
    /// \param secret - The secret which used by HMAC algorithm .
    /// \return - Return 32 byte hmac hash.
    std::vector<gsl::byte> hmacSha256(Bytes toSignData, Bytes secret);

    /// Exception class used by crypto module for any OpenSSL error.
    using namespace std::string_literals;

    class CryptoException : public std::runtime_error {
    public:
        explicit CryptoException(std::string &&what, int code = 1) :
                std::runtime_error{"Error code "s + std::to_string(code) + ". " + move(what)},
                m_code{code} {}

        int code() const noexcept {
            return m_code;
        }

    private:
        int m_code;
    };

    /// Utility method to throw exception when there is an OpenSSL error.
    /// \param errorStringPrefix - The error message.
    /// \param fileName - The source file name.
    /// \param lineNumber - The current line number in the source file.
    void _ThrowOpensslException(std::string &&errorStringPrefix, const char *fileName, unsigned int lineNumber);

    /// Throws virtru::crypto::CryptoException if rc is not equal 1
    /// \param rc OpenSSL return code to compare
    /// \param error_string_prefix Error string prefix
    template<typename T>
    void checkOpensslResult(int r, T&& prefix) {
        if (r != 1) {
            ThrowOpensslException (std::forward<T>(prefix));
        }
    }

    /// Generate a symmetric key of a given key size.
    /// \param keySize - The key size.
    /// \return - Return ByteArray with key of specified key size.
    template<std::size_t keySize>
    auto symmetricKey() {
        ByteArray<keySize> a;
        checkOpensslResult(RAND_bytes(toUchar(a.data()), keySize), "Failed to generate symmetric key.");
        return a;
    }

    /// Base64 encode the given data.
    /// \param data - The data(Bytes) to be encoded.
    /// \return std::string - The base64 encoded result.
    std::string base64Encode(Bytes data);

    /// Base64 encode the given data.
    /// \param data - The data(std::string) to be encoded.
    /// \return std::string - The base64 encoded result.
    std::string base64Encode(const std::string& data);

    /// Base64 decode the given data.
    /// \param data - The data(Bytes) to be decoded.
    /// \return std::string - The base64 decoded result.
    std::string base64Decode(Bytes data);

    /// Base64 decode the given data.
    /// \param data - The data(Bytes) to be decoded.
    /// \return std::string - The base64 decoded result.
    std::string base64Decode(const std::string& data);

    /// Base64Url encode the given data.
    /// \param data - The data(Bytes) to be encoded.
    /// \return std::string - The base64url encoded result.
    std::string base64UrlEncode(Bytes data);

    /// Base64Url encode the given data.
    /// \param data - The data(std::string) to be encoded.
    /// \return std::string - The base64url encoded result.
    std::string base64UrlEncode(const std::string& data);

    /// Base64Url decode the given data.
    /// \param data - The data(Bytes) to be decoded.
    /// \return std::string - The base64url decoded result.
    std::string base64UrlDecode(Bytes data);

    /// Base64Url decode the given data.
    /// \param data - The data(Bytes) to be decoded.
    /// \return std::string - The base64url decoded result.
    std::string base64UrlDecode(const std::string& data);
}  // namespace virtru::crypto

#endif //VIRTRU_CRYPTO_UTILS_H
