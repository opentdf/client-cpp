/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/04.
//

#include <array>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <cstddef>

#include <boost/beast/core/detail/base64.hpp>

#include "bytes.h"
#include "crypto_utils.h"
#include "tdf_exception.h"
#include "openssl_deleters.h"

namespace virtru::crypto {

    //Constants
    constexpr auto kOpenSslErrorStringLen = 256;
    using byte = unsigned char;

    /// Calculate Sha256 of the given buffer and return the hash in hex format. On error OpensslException is thrown.
    std::string hexHashSha256(Bytes data) {
        auto hash = calculateSHA256(data);
        return hex(hash);
    }

    /// Calculate Sha256 of the given buffer and return the hash in binary format. On error OpensslException is thrown.
    std::array<gsl::byte, 32u> calculateSHA256(Bytes data) {

        if (static_cast<unsigned long>(data.size()) > std::numeric_limits<size_t>::max()) {
            ThrowException("Input buffer is too big for calculating sha256 hash.");
        }

        EVP_MD_CTX_free_ptr context{EVP_MD_CTX_create()};
        if (!context) {
            ThrowOpensslException("EVP_MD_CTX_new failed.");
        }

        if(!EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr)) {
            ThrowOpensslException("EVP_DigestInit_ex failed.");
        }

        if(!EVP_DigestUpdate(context.get(), data.data(), static_cast<size_t>(data.size()))) {
            ThrowOpensslException("EVP_DigestUpdate failed.");
        }

        constexpr auto hashSize = 32;
        std::array<gsl::byte, hashSize> hash{};
        unsigned int lengthOfHash = 0;
        if(!EVP_DigestFinal_ex(context.get(), reinterpret_cast<std::uint8_t*>(hash.data()), &lengthOfHash)) {
            ThrowOpensslException("EVP_DigestFinal_ex failed.");
        }

        if (hashSize != lengthOfHash) {
            ThrowOpensslException ("SHA256 failed");
        }

        return hash;
    }

    std::string hex(Bytes data) {

        if (static_cast<unsigned long>(data.size() * 2) > std::numeric_limits<std::string::size_type>::max()) {
            ThrowException("Input buffer is too big for converting to hex.");
        }

        std::vector<char> res(static_cast<unsigned long>(data.size() * 2));
        std::size_t i = 0;

        for (auto c : data) {
            static constexpr char syms [ ] = "0123456789abcdef";
            auto n = std::to_integer <unsigned> ( c );
            res[i ++] = syms[n >> 4];
            res[i ++] = syms[n & 0xf];
        }

        return std::string{res.begin(), res.end()};
    }

    /// Create an HMAC  of the given data and return the hash in hex format. On error OpensslException is thrown.
    std::string hexHmacSha256(Bytes toSignData, Bytes secret) {
        auto digest = hmacSha256(toSignData, secret);
        return  hex(toBytes(digest));
    }

    /// Create an HMAC  of the given data and return the hash in binary format. On error OpensslException is thrown.
    std::vector<gsl::byte> hmacSha256(Bytes toSignData, Bytes secret) {

        if (static_cast<unsigned long>(toSignData.size()) > std::numeric_limits<size_t>::max()) {
            ThrowException("Input buffer is too big for calculating HMAC.");
        }

        if (secret.size() > std::numeric_limits<int>::max()) {
            ThrowException("HMAC secret is too big.");
        }

        std::vector<gsl::byte> digest(32);;
        unsigned digestSize = 0;
        auto returnCode = HMAC (
                EVP_sha256(),
                secret.data(),
                static_cast<int>(secret.size()),
                reinterpret_cast <const unsigned char*> (toSignData.data()),
                static_cast<size_t>(toSignData.size()),
                reinterpret_cast <unsigned char*> (digest.data()),
                &digestSize
        );

        if (!returnCode || digestSize != digest.size()) {
            ThrowOpensslException ("HMAC failed");
        }

        return digest;
    }

    /// Utility method to throw exception when there is an OpenSSL error.
    void _ThrowOpensslException(std::string&& errorStringPrefix, const char* fileName, unsigned int lineNumber)
    {
        std::ostringstream os;
        os << " [" << fileName << ":" << lineNumber << "] ";

        std::array<char, kOpenSslErrorStringLen> openssl_error_string_buffer{};
        auto error = ERR_get_error();
        ERR_error_string_n(error, openssl_error_string_buffer.data(), openssl_error_string_buffer.size());
        throw CryptoException {
                os.str() + move (errorStringPrefix) + openssl_error_string_buffer.data(),
                static_cast<int>(error)
        };
    }

    // Base64 encode the given data(Bytes).
    std::string base64Encode(Bytes data) {
        std::string dest;
        dest.resize(boost::beast::detail::base64::encoded_size(data.size()));
        dest.resize(boost::beast::detail::base64::encode(&dest[0], data.data(), data.size()));
        return dest;
    }

    /// Base64 encode the given data(std::string).
    std::string base64Encode(const std::string& data) {
        std::string dest;
        dest.resize(boost::beast::detail::base64::encoded_size(data.size()));
        dest.resize(boost::beast::detail::base64::encode(&dest[0], data.data(), data.size()));
        return dest;
    }

    /// Base64 decode the given data(Bytes).
    std::string base64Decode(Bytes data) {

        std::string dest;
        dest.resize(boost::beast::detail::base64::decoded_size(data.size()));
        auto const result = boost::beast::detail::base64::decode(&dest[0],
                reinterpret_cast <char const*>(data.data()), data.size());
        dest.resize(result.first);
        return dest;
    }

    /// Base64 decode the given data(std::string).
    std::string base64Decode(const std::string& data) {

        std::string dest;
        dest.resize(boost::beast::detail::base64::decoded_size(data.size()));
        auto const result = boost::beast::detail::base64::decode(&dest[0], data.data(), data.size());
        dest.resize(result.first);
        return dest;
    }

    /// Base64Url routines from https://gist.github.com/darelf/0f96e1d313e1d0da5051e1a6eff8d329
    
    /*
    Base64 translates 24 bits into 4 ASCII characters at a time. First,
    3 8-bit bytes are treated as 4 6-bit groups. Those 4 groups are
    translated into ASCII characters. That is, each 6-bit number is treated
    as an index into the ASCII character array.
    If the final set of bits is less 8 or 16 instead of 24, traditional base64
    would add a padding character. However, if the length of the data is
    known, then padding can be eliminated.
    One difference between the "standard" Base64 is two characters are different.
    See RFC 4648 for details.
    This is how we end up with the Base64 URL encoding.
    */
    
    const char base64_url_alphabet[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };
    
    std::string base64UrlEncode(Bytes in) {
        std::string out;
        int val =0, valb=-6;
        size_t len = in.size();
        unsigned int i = 0;
        for (i = 0; i < len; i++) {
            unsigned char c = static_cast<unsigned char>(in[i]);
            val = (val<<8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) {
            out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
        }
        return out;
    }
    
    std::string base64UrlEncode(const std::string & in) {
        return base64UrlEncode(toBytes(in));
    }
    
    std::string base64UrlDecode(Bytes in) {
        std::string out;
        std::vector<int> T(256, -1);
        unsigned int i;
        for (i =0; i < 64; i++) T[base64_url_alphabet[i]] = i;
    
        int val = 0, valb = -8;
        for (i = 0; i < in.size(); i++) {
            unsigned char c = static_cast<unsigned char>(in[i]);
            if (T[c] == -1) break;
            val = (val<<6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(char((val>>valb)&0xFF));
                valb -= 8;
            }
        }
        return out;
    }
    
    std::string base64UrlDecode(const std::string & in) {
        return base64UrlDecode(toBytes(in));
    }
    
} // namespace virtru::crypto
