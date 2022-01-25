/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/28
//

#ifndef VIRTRU_ECC_MODE_H
#define VIRTRU_ECC_MODE_H

#include "crypto/crypto_utils.h"

namespace virtru::nanotdf {

    using namespace virtru::crypto;

    /***********************ECC And Binding Mode**************************
    | This section describes ECC params and  Policy binding strategy to use.
    | The Policy Binding strategy is either using a GMAC tag or
    | an ECDSA signature. The signature size depends on the size of ECC
    | Params used.
    |
    | Section               | Bit Length  | Bit start index |
    |-----------------------|-------------|-----------------|
    | USE_ECDSA_BINDING     | 1           | 7               |
    | UNUSED                | 4           | 3               |
    | ECC Params Enum       | 3           | 0               |
    |
    | The Binding section contains a cryptographic binding of the payload key to the
    | policy. The type of the binding is either a GMAC or an ECDSA signature.
    | The binding type is determined by the [ECC And Binding Mode] Section.
    | BM = Binding method (either ECDSA or a GMAC)
    | BS = Binding Signature
    | PB = Plaintext of Policy Body
    | BS = BM(SHA256(PB))
    |
    ************************ECC And Binding Mode**************************/

    class ECCMode {
    public: /// Enums


    public:
        /// Constructor for empty object.
        ECCMode();

        /// Constructor to update the object.
        /// \param value - The value with ecc mode
        explicit ECCMode(gsl::byte value);

        /// Destructors
        ~ECCMode();

        /// Copy constructor
        ECCMode(const ECCMode& eccMode);

        /// Assignment operator
        ECCMode& operator=(const ECCMode& eccMode);

        /// Move copy constructor
        ECCMode(ECCMode&& eccMode) noexcept;

        /// Move assignment operator
        ECCMode& operator=(ECCMode&& eccMode) noexcept;

    public: // Interface
        /// Set the flag to enable/disable ECDSABinding.
        /// \param The flag to enable/disable ECDSABinding.
        void setECDSABinding(bool flag);

        /// Set the Elliptic Curve type.
        /// \param The Elliptic Curve type.
        void setEllipticCurve(EllipticCurve curve);

        /// Return the EllipticCurve type.
        /// \return The EllipticCurve type.
        EllipticCurve getEllipticCurveType() const;

        /// Return true if the ECDSA binding is set.
        /// \return True if the ECDSA binding is set.
        bool isECDSABindingEnabled() const;

        /// Return the string value of the curve.
        /// \param param - The curve mode enum
        /// \return The string value of the curve.
        std::string getCurveName() const;

        /// Return the ecc mode as byte value.
        /// \return The ecc mode as byte value.
        gsl::byte getECCModeAsByte() const;

    public: // Static
        /// Return the string value of the curve.
        /// \param param - The curve mode enum
        /// \return The string value of the curve.
        static std::string GetEllipticCurveName(EllipticCurve curve);

        /// Return the size of key of the given curve.
        /// \param curve - The curve value.
        /// \return The size of key of the given curve.
        static std::uint8_t GetECKeySize(EllipticCurve curve);

        /// Return the compressed size of public key of the given curve.
        /// \param curve - The curve value.
        /// \return The compressed size of public key of the given curve.
        static std::uint8_t GetECCompressedPubKeySize(EllipticCurve curve);

    private: // Data
        /// Struct which holds the ecc mode information.
        struct ECCModeStruct {
            std::uint8_t  curveMode: 3;
            std::uint8_t  unused: 4;
            std::uint8_t  useECDSABinding: 1;
        };
        ECCModeStruct   m_data{};
    };
}

#endif //VIRTRU_ECC_MODE_H
