//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/29
//  Copyright 2020 Virtru Corporation
//

#include "tdf_exception.h"
#include "symmetric_and_payload_config.h"

namespace virtru::nanotdf {

    /// Constructor for empty object.
    SymmetricAndPayloadConfig::SymmetricAndPayloadConfig() {
        m_data.symmetricCipherEnum = 0x0; // AES_256_GCM_64_TAG
        m_data.signatureECCMode = 0x00; // SECP256R1
        m_data.hasSignature = 1;
    }

    /// Constructor to update the object.
    /// \param value - - The value with symmetric and payload config.
    SymmetricAndPayloadConfig::SymmetricAndPayloadConfig(gsl::byte value) {

        auto cipherType = static_cast<std::uint8_t>(value) & 0x0F; // first 4 bits
        setSymmetricCipherType(NanoTDFCipher(cipherType));

        auto signatureECCMode = (static_cast<std::uint8_t>(value) >> 4u)  & 0x07;
        setSignatureECCMode(EllipticCurve(signatureECCMode));

        auto hasSignature =(static_cast<std::uint8_t>(value) >> 7u) & 0x01; // most significant bit
        m_data.hasSignature = hasSignature;
    }

    // Provide default implementation.
    SymmetricAndPayloadConfig::~SymmetricAndPayloadConfig()  = default;
    SymmetricAndPayloadConfig::SymmetricAndPayloadConfig(const SymmetricAndPayloadConfig&) = default;
    SymmetricAndPayloadConfig& SymmetricAndPayloadConfig::operator=(const SymmetricAndPayloadConfig&) = default;
    SymmetricAndPayloadConfig::SymmetricAndPayloadConfig(SymmetricAndPayloadConfig&&) noexcept = default;
    SymmetricAndPayloadConfig& SymmetricAndPayloadConfig::operator=(SymmetricAndPayloadConfig&&) noexcept = default;

    /// Set the flag to enable/disable signature for the payload.
    void SymmetricAndPayloadConfig::setHasSignature(bool flag) {
        if (flag) {
            m_data.hasSignature = 1;
        } else {
            m_data.hasSignature = 0;
        }
    }

    /// Set the ecc mode for the signature.
    void SymmetricAndPayloadConfig::setSignatureECCMode(EllipticCurve curve) {
        switch (curve) {
            case EllipticCurve::SECP256R1:
                m_data.signatureECCMode = 0x00;
                break;
            case EllipticCurve::SECP384R1:
                m_data.signatureECCMode = 0x01;
                break;
            case EllipticCurve::SECP521R1:
                m_data.signatureECCMode = 0x02;
                break;
            case EllipticCurve::SECP256K1:
                ThrowException("SDK doesn't support 'secp256k1' curve");
                break;
            default:
                ThrowException("Unsupported ECC algorithm.");
                break;
        }
    }

    /// Set the symmetric cipher type.
    void SymmetricAndPayloadConfig::setSymmetricCipherType(NanoTDFCipher cipherType) {

        switch (cipherType) {
            case NanoTDFCipher::AES_256_GCM_64_TAG:
                m_data.symmetricCipherEnum = 0x00;
                break;
            case NanoTDFCipher::AES_256_GCM_96_TAG:
                m_data.symmetricCipherEnum = 0x01;
                break;
            case NanoTDFCipher::AES_256_GCM_104_TAG:
                m_data.symmetricCipherEnum = 0x02;
                break;
            case NanoTDFCipher::AES_256_GCM_112_TAG:
                m_data.symmetricCipherEnum = 0x03;
                break;
            case NanoTDFCipher::AES_256_GCM_120_TAG:
                m_data.symmetricCipherEnum = 0x04;
                break;
            case NanoTDFCipher::AES_256_GCM_128_TAG:
                m_data.symmetricCipherEnum = 0x05;
                break;
            case NanoTDFCipher::EAD_AES_256_HMAC_SHA_256:
                m_data.symmetricCipherEnum = 0x06;
                break;
            default:
                ThrowException("Unsupported symmetric cipher for signature.");
                break;
        }
    }

    /// Return true if signature is enabled for the payload.
    bool SymmetricAndPayloadConfig::hasSignature() const {
        return m_data.hasSignature;
    }

    /// Return the ecc mode for the signature.
    EllipticCurve SymmetricAndPayloadConfig::getSignatureECCMode() const {
        return EllipticCurve(m_data.signatureECCMode);
    }

    /// Return the cipher type.
    NanoTDFCipher SymmetricAndPayloadConfig::getCipherType() const {
        return NanoTDFCipher(m_data.symmetricCipherEnum);
    }

    /// Return the symmetric and payload config value as byte value.
    gsl::byte SymmetricAndPayloadConfig::getSymmetricAndPayloadConfigAsByte() const {
        std::uint8_t value = m_data.hasSignature << 7 | m_data.signatureECCMode << 4 | m_data.symmetricCipherEnum;
        static_assert(sizeof(std::uint8_t) == sizeof(gsl::byte), "gsl::byte and std::uint8_t are not same size");

        return static_cast<gsl::byte>(value);
    }

    /// Return the size of auth tag to be used for aes gcm encryption.
    std::uint8_t SymmetricAndPayloadConfig::SizeOfAuthTagForCipher(NanoTDFCipher cipherType) {
        switch (cipherType) {
            case NanoTDFCipher::AES_256_GCM_64_TAG:
                return 8;
            case NanoTDFCipher::AES_256_GCM_96_TAG:
                return 12;
            case NanoTDFCipher::AES_256_GCM_104_TAG:
                return 13;
            case NanoTDFCipher::AES_256_GCM_112_TAG:
                return 14;
            case NanoTDFCipher::AES_256_GCM_120_TAG:
                return 15;
            case NanoTDFCipher::AES_256_GCM_128_TAG:
                return 16;
            case NanoTDFCipher::EAD_AES_256_HMAC_SHA_256:
                return 32;
            default:
                ThrowException("Unsupported symmetric cipher for signature.");
                break;
        }
    }

    /// Return the string representation of cipher type(logging purpose).
    std::string SymmetricAndPayloadConfig::CipherTypeAsString(NanoTDFCipher cipherType) {
        switch (cipherType) {
            case NanoTDFCipher::AES_256_GCM_64_TAG:
                return "aes-256-gcm-64-bit-tag";
            case NanoTDFCipher::AES_256_GCM_96_TAG:
                return "aes-256-gcm-96-bit-tag";
            case NanoTDFCipher::AES_256_GCM_104_TAG:
                return "aes-256-gcm-104-bit-tag";
            case NanoTDFCipher::AES_256_GCM_112_TAG:
                return "aes-256-gcm-112-bit-tag";
            case NanoTDFCipher::AES_256_GCM_120_TAG:
                return "aes-256-gcm-120-bit-tag";
            case NanoTDFCipher::AES_256_GCM_128_TAG:
                return "aes-256-gcm-128-bit-tag";
            case NanoTDFCipher::EAD_AES_256_HMAC_SHA_256:
                return "aes-256-gcm-256-bit-tag";
            default:
                ThrowException("Unsupported symmetric cipher for signature.");
                break;
        }
    }
}
