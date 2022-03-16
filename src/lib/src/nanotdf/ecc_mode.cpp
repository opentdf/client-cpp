/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/29
//

#include "tdf_exception.h"
#include "ecc_mode.h"

namespace virtru::nanotdf {

    /// Constructor for empty object.
    ECCMode::ECCMode() {
        m_data.curveMode = 0x00; // SECP256R1
        m_data.unused = 0; // fill with zero(unused)
        m_data.useECDSABinding = 0; // enable ECDSA binding
    }

    /// Constructor to update the object.
    ECCMode::ECCMode(gsl::byte value) {
        auto curveMode = static_cast<std::uint8_t>(value) & 0x07; // first 3 bits
        setEllipticCurve(EllipticCurve(curveMode));
        auto useECDSABinding = (static_cast<std::uint8_t>(value) >> 7) & 0x01; // most significant bit
        m_data.useECDSABinding = useECDSABinding;
    }

    // Provide default implementation.
    ECCMode::~ECCMode()  = default;
    ECCMode::ECCMode(const ECCMode&) = default;
    ECCMode& ECCMode::operator=(const ECCMode&) = default;
    ECCMode::ECCMode(ECCMode&&) noexcept = default;
    ECCMode& ECCMode::operator=(ECCMode&&)noexcept = default;

    /// Set the flag to enable/disable ECDSABinding.
    void ECCMode::setECDSABinding(bool flag) {
        if (flag) {
            m_data.useECDSABinding = 1;
        } else {
            m_data.useECDSABinding = 0;
        }
    }

    /// Set the ecc curve.
    void ECCMode::setEllipticCurve(EllipticCurve curve) {
        switch (curve) {
            case EllipticCurve::SECP256R1:
                m_data.curveMode = 0x00;
                break;
            case EllipticCurve::SECP384R1:
                m_data.curveMode = 0x01;
                break;
            case EllipticCurve::SECP521R1:
                m_data.curveMode = 0x02;
                break;
            case EllipticCurve::SECP256K1:
                ThrowException("SDK doesn't support 'secp256k1' curve");
                break;
            default:
                ThrowException("Unsupported ECC algorithm.");
                break;
        }
    }

    /// Return the EllipticCurve type.
    EllipticCurve ECCMode::getEllipticCurveType() const {
        return EllipticCurve(m_data.curveMode);
    }

    /// Return true if the ECDSA binding is set.
    bool ECCMode::isECDSABindingEnabled() const {
        return m_data.useECDSABinding;
    }

    /// Return the string value of the curve.
    std::string ECCMode::getCurveName() const {

        auto curve = EllipticCurve(m_data.curveMode);
        return GetEllipticCurveName(curve);
    }

    /// Return the ecc mode as byte value.
    gsl::byte ECCMode::getECCModeAsByte() const {
        std::uint8_t value = (m_data.useECDSABinding << 7) | m_data.curveMode;
        static_assert(sizeof(std::uint8_t) == sizeof(gsl::byte), "gsl::byte and std::uint8_t are not same size");

        return static_cast<gsl::byte>(value);
    }

    /// Return the string value of the curve.
    std::string ECCMode::GetEllipticCurveName(EllipticCurve curve)  {

        switch (curve) {
            case EllipticCurve::SECP256R1:
                //SECG secp256r1 is the same as X9.62 prime256v1
                return "prime256v1";
            case EllipticCurve::SECP384R1:
                return "secp384r1";
            case EllipticCurve::SECP521R1:
                return "secp521r1";
            case EllipticCurve::SECP256K1:
                ThrowException("SDK doesn't support 'secp256k1' curve");
                break;
            default:
                ThrowException("Unsupported ECC algorithm.");
                break;
        }
    }

    /// Return the size of key of the given curve.
    std::uint8_t ECCMode::GetECKeySize(EllipticCurve curve) {
        switch (curve) {
            case EllipticCurve::SECP256K1:
                ThrowException("SDK doesn't support 'secp256k1' curve");
            case EllipticCurve::SECP256R1:
                return 32;
            case EllipticCurve::SECP384R1:
                return 48;
            case EllipticCurve::SECP521R1:
                return 66;
            default:
                ThrowException("Unsupported ECC algorithm.");
                break;
        }
    }

    /// Return the compressed size of public key of the given curve.
    std::uint8_t ECCMode::GetECCompressedPubKeySize(EllipticCurve curve) {
        switch (curve) {
            case EllipticCurve::SECP256K1:
                ThrowException("SDK doesn't support 'secp256k1' curve");
            case EllipticCurve::SECP256R1:
                return 33;
            case EllipticCurve::SECP384R1:
                return 49;
            case EllipticCurve::SECP521R1:
                return 67;
            default:
                ThrowException("Unsupported ECC algorithm.");
                break;
        }
    }
}
