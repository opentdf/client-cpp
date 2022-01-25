/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/01
//

#include "tdf_exception.h"
#include "header.h"

namespace virtru::nanotdf {

    /// Constructor for empty object.
    Header::Header() { }

    /// Constructor the object by reading the buffer.
    /// \param bytes - The bytes with nano tdf header info.
    Header::Header(Bytes bytes) {

        ///
        /// Read the magic number and version.
        ///
        std::array<char, 3> magicNumberAndVersion{};
        std::memcpy(magicNumberAndVersion.data(), bytes.data(), magicNumberAndVersion.size());

        if (magicNumberAndVersion != m_magicNumberAndVersion) {
            ThrowException("Invalid magic number and version in nano tdf.");
        }

        // Adjust the bytes.
        bytes = bytes.subspan(magicNumberAndVersion.size());

        ///
        /// Read the Kas locator
        ///
        ResourceLocator kasLocator{bytes};

        // Adjust the bytes.
        bytes = bytes.subspan(kasLocator.getTotalSize());

        m_kasLocator = std::move(kasLocator);

        ///
        /// Read the ECC mode;
        ///
        gsl::byte eccModeValue;
        std::memcpy(&eccModeValue, bytes.data(), sizeof(eccModeValue));
        ECCMode eccMode{eccModeValue};

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(eccModeValue));

        m_eccMode = std::move(eccMode);

        ///
        /// Read Payload + Sig Mode
        ///
        gsl::byte payloadConfigValue;
        std::memcpy(&payloadConfigValue, bytes.data(), sizeof(payloadConfigValue));
        SymmetricAndPayloadConfig payloadConfig{payloadConfigValue};

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(payloadConfigValue));

        m_payloadConfig = std::move(payloadConfig);

        ///
        /// Read Payload Info
        ///
        PolicyInfo policyInfo{bytes, m_eccMode};

        // Adjust the bytes.
        bytes = bytes.subspan(policyInfo.getTotalSize());

        m_policyInfo = std::move(policyInfo);

        ///
        /// Read Ephemeral Key
        ///
        auto compressedPubKeySize = ECCMode::GetECCompressedPubKeySize(m_eccMode.getEllipticCurveType());
        m_ephemeralKey.resize(compressedPubKeySize);
        std::memcpy(m_ephemeralKey.data(), bytes.data(), compressedPubKeySize);
    }

    // Provide default implementation.
    Header::~Header()  = default;
    Header::Header(const Header&) = default;
    Header& Header::operator=(const Header&) = default;
    Header::Header(Header&&) noexcept = default;
    Header& Header::operator=(Header&&)  noexcept = default;

    /// Return the magic number and version used in nano tdf.
    Bytes Header::getMagicNumberAndVersion() const {
        return toBytes(m_magicNumberAndVersion);
    }

    /// Set the kas locator for this header object.
    void Header::setKasLocator(ResourceLocator&& kasLocator) {
        m_kasLocator = std::move(kasLocator);
    }

    /// Set the kas locator for this header object.
    void Header::setKasLocator(const ResourceLocator& kasLocator) {
        m_kasLocator = kasLocator;
    }

    /// Return the kas locator from this header.
    ResourceLocator Header::getKasLocator() const {
        return m_kasLocator;
    }

    /// Set the ECC mode for this header object.
    void Header::setECCMode(ECCMode&& eccMode) {
        m_eccMode = std::move(eccMode);
    }

    /// Set the ECC mode for this header object.
    void Header::setECCMode(const ECCMode& eccMode) {
        m_eccMode = eccMode;
    }

    /// Return the ECC mode form this header object.
    ECCMode Header::getECCMode() const {
        return m_eccMode;
    }

    /// Set the payload config for this header object.
    void Header::setPayloadConfig(SymmetricAndPayloadConfig&& payloadConfig) {
        m_payloadConfig = std::move(payloadConfig);
    }

    /// Set the payload config for this header object.
    void Header::setPayloadConfig(const SymmetricAndPayloadConfig& payloadConfig) {
        m_payloadConfig = payloadConfig;
    }

    /// Return the payload config form this header object.
    SymmetricAndPayloadConfig Header::getPayloadConfig() const {
        return m_payloadConfig;
    }

    /// Set the policy info for this header object.
    void Header::setPolicyInfo(PolicyInfo&& policyInfo) {
        m_policyInfo = std::move(policyInfo);
    }

    /// Set the policy info for this header object.
    void Header::setPolicyInfo(const PolicyInfo& policyInfo) {
        m_policyInfo = policyInfo;
    }

    /// Return the policy info form this header object.
    PolicyInfo Header::getPolicyInfo() const {
        return m_policyInfo;
    }

    /// Set the ephemeral key for this header object
    void Header::setEphemeralKey(Bytes bytes) {

        auto compressedPubKeySize = ECCMode::GetECCompressedPubKeySize(m_eccMode.getEllipticCurveType());
        if (bytes.size() < compressedPubKeySize) {
            ThrowException("Failed to read ephemeral key - invalid buffer size.");
        }

        m_ephemeralKey.resize(compressedPubKeySize);
        std::memcpy(m_ephemeralKey.data(), bytes.data(), compressedPubKeySize);

    }

    /// Return the reference to the data of ephemeral key.
    Bytes Header::getEphemeralKey() const {
        return toBytes(m_ephemeralKey);
    }

    /// Get the total size required to store Header data.
    std::uint16_t Header::getTotalSize() const {

        std::uint16_t totalSize = 0;

        // Add the size of magic number and version size.
        totalSize += m_magicNumberAndVersion.size();

        // Add the size of kas locator.
        totalSize += m_kasLocator.getTotalSize();

        // Add the size of ECC mode.
        totalSize += sizeof(std::uint8_t);

        // Add the size of payload config.
        totalSize += sizeof(std::uint8_t);

        // Add the size of policy info.
        totalSize += m_policyInfo.getTotalSize();

        // Add the size of ephemeral key.
        totalSize += m_ephemeralKey.size();

        return totalSize;
    }

    /// Write this object data into the buffer and return the amount of bytes
    std::uint16_t Header::writeIntoBuffer(WriteableBytes bytes) const{

        if (bytes.size() < getTotalSize()) {
            ThrowException("Failed to write header - invalid buffer size.");
        }

        std::uint16_t totalBytesWritten = 0;

        // Write the magic number and version
        std::memcpy(bytes.data(), m_magicNumberAndVersion.data(), m_magicNumberAndVersion.size());

        // Adjust the bytes.
        bytes = bytes.subspan(m_magicNumberAndVersion.size());
        totalBytesWritten += m_magicNumberAndVersion.size();

        // Write the kas locator.
        auto kasLocatorSize = m_kasLocator.writeIntoBuffer(bytes);

        // Adjust the bytes.
        bytes = bytes.subspan(kasLocatorSize);
        totalBytesWritten += kasLocatorSize;

        // Write the eccMode.
        gsl::byte eccMode = m_eccMode.getECCModeAsByte();
        std::memcpy(bytes.data(), &eccMode, sizeof(eccMode));

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(eccMode));
        totalBytesWritten += sizeof(eccMode);

        // Write the payload config.
        gsl::byte payloadConfig = m_payloadConfig.getSymmetricAndPayloadConfigAsByte();
        std::memcpy(bytes.data(), &payloadConfig, sizeof(payloadConfig));

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(payloadConfig));
        totalBytesWritten += sizeof(payloadConfig);

        // Write the policy info.
        auto policyInfoSize = m_policyInfo.writeIntoBuffer(bytes);

        // Adjust the bytes.
        bytes = bytes.subspan(policyInfoSize);
        totalBytesWritten += policyInfoSize;

        // Write the ephemeral key..
        std::memcpy(bytes.data(), m_ephemeralKey.data(), m_ephemeralKey.size());

        // Adjust the bytes.
        bytes = bytes.subspan(m_ephemeralKey.size());
        totalBytesWritten += m_ephemeralKey.size();

        return totalBytesWritten;
    }
}
