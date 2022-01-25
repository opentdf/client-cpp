/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/29
//

#ifndef VIRTRU_SYMMETRIC_AND_PAYLOAD_CONFIG_H
#define VIRTRU_SYMMETRIC_AND_PAYLOAD_CONFIG_H

#include "tdf_constants.h"
#include "crypto/crypto_utils.h"

namespace virtru::nanotdf {

    using namespace virtru::crypto;

    /***********************Symmetric + Payload Config**************************
    | This section describe the symmetric ciphers for encrypted payloads. This cipher
    | applies to both the Payload and the Policy of the nanotdf. The fields are as follows:
    |
    | Section               | Bit Length  | Bit start index |
    |-----------------------|-------------|-----------------|
    | HAS_SIGNATURE         | 1           | 7               |
    | Signature ECC Mode    | 3           | 4               |
    | Symmetric Cipher Enum | 4           | 0               |
    ***********************Symmetric + Payload Config**************************/

    class SymmetricAndPayloadConfig {
    public:
        /// Constructor for empty object.
        SymmetricAndPayloadConfig();

        /// Constructor to update the object.
        /// \param value - - The value with symmetric and payload config.
        explicit SymmetricAndPayloadConfig(gsl::byte value);

        /// Destructors
        ~SymmetricAndPayloadConfig();

        /// Copy constructor
        SymmetricAndPayloadConfig(const SymmetricAndPayloadConfig& config);

        /// Assignment operator
        SymmetricAndPayloadConfig& operator=(const SymmetricAndPayloadConfig& config);

        /// Move copy constructor
        SymmetricAndPayloadConfig(SymmetricAndPayloadConfig&& config) noexcept;

        /// Move assignment operator
        SymmetricAndPayloadConfig& operator=(SymmetricAndPayloadConfig&& config) noexcept ;

    public: // Interface
        /// Set the flag to enable/disable signature for the payload.
        /// \param The flag to enable/disable signature for the payload.
        void setHasSignature(bool flag);

        /// Set the ecc mode for the signature.
        /// \param curve - The curve value.
        void setSignatureECCMode(EllipticCurve curve);

        /// Set the symmetric cipher type.
        /// \param The symmetric cipher type.
        void setSymmetricCipherType(NanoTDFCipher cipherType);

        /// Return true if signature is enabled for the payload.
        /// \return True if signature is enabled for the payload.
        bool hasSignature() const;

        /// Return the ecc mode for the signature.
        /// \return The curve type.
        EllipticCurve getSignatureECCMode() const;

        /// Return the cipher type.
        /// \return The cipher type.
        NanoTDFCipher getCipherType() const;

        /// Return the symmetric and payload config value as byte value.
        /// \return The symmetric and payload config value as byte value.
        gsl::byte getSymmetricAndPayloadConfigAsByte() const;

    public: // Static
        /// Return the size of auth tag in bytes to be used for aes gcm encryption.
        /// \param cipherType - The cipher type.
        /// \return The size of auth tag in bytes to be used for aes gcm encryption.
        static std::uint8_t SizeOfAuthTagForCipher(NanoTDFCipher cipherType);

        /// Return the string representation of cipher type(logging purpose).
        /// \param cipherType - The cipher type
        /// \return The string representation of cipher type.
        static std::string CipherTypeAsString(NanoTDFCipher cipherType);

    private: // Data
        /// Struct which holds the ecc mode information.
        struct _SymmetricAndPayloadConfig {
            std::uint8_t  symmetricCipherEnum: 4; // Symmetric cipher.
            std::uint8_t  signatureECCMode: 3; // Signature ECC mode.
            std::uint8_t  hasSignature: 1; // most significant bit.
        };
        _SymmetricAndPayloadConfig   m_data{};
    };
}

#endif //VIRTRU_SYMMETRIC_AND_PAYLOAD_CONFIG_H
