/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/25.
//

#ifndef VIRTRU_CONSTANTS_H
#define VIRTRU_CONSTANTS_H

#include <string_view>
#include <functional>
namespace virtru {

#ifdef SWIG_JAVA
    typedef int8_t VBYTE;
#else
    typedef uint8_t VBYTE;
#endif

    enum class KeyType {
        split /// default
    };

    enum class CipherType {
        Aes256GCM /// default
        ,Aes265CBC
    };

    enum class IntegrityAlgorithm {
        HS256  /// default
        ,GMAC
    };

    enum class KeyAccessType {
        Remote /// default
        ,Wrapped /// The key is embedded in the TDF
    };

    enum class Protocol {
        Zip  /// TDF format is zip
        ,Html  /// Default format is HTML
        ,Xml
    };

    /// Defines a log level.
    enum class LogLevel {
        Trace  /// Most detailed output
        ,Debug
        ,Info
        ,Warn
        ,Error
        ,Fatal  /// Least detailed output
        ,Current  /// no-op, value indicates current level should be retained
    };

    enum class Status {
        Success  /// Operation completed successfully
        ,Failure   /// Operation did not complete successfully
    };

    struct BufferSpan{
        const std::uint8_t* data;
        std::size_t dataLength;
    };

    using TDFDataSourceCb = std::function < BufferSpan(Status &) >;
    using TDFDataSinkCb = std::function < Status(BufferSpan)>;

    enum class EllipticCurve : std::uint8_t {
        SECP256R1 = 0x00,
        SECP384R1 = 0x01,
        SECP521R1 = 0x02,
        SECP256K1 = 0x03
    };

    enum class NanoTDFPolicyType : std::uint8_t {
        REMOTE_POLICY = 0x00,
        EMBEDDED_POLICY_PLAIN_TEXT = 0x01,
        EMBEDDED_POLICY_ENCRYPTED = 0x02,
        EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS = 0x03
    };

    enum class NanoTDFCipher : std::uint8_t {
        AES_256_GCM_64_TAG = 0x00,
        AES_256_GCM_96_TAG = 0x01,
        AES_256_GCM_104_TAG = 0x02,
        AES_256_GCM_112_TAG = 0x03,
        AES_256_GCM_120_TAG = 0x04,
        AES_256_GCM_128_TAG = 0x05,
        EAD_AES_256_HMAC_SHA_256 = 0x06
    };

    // Total unique IVs(2^23 -1) used for encrypting the nano tdf payloads
    // IV starts from 1 since the 0 IV is reserved for policy encryption
    const uint32_t kNTDFMaxKeyIterations           = 8388606;

}  // namespace virtru

#endif //VIRTRU_CONSTANTS_H
