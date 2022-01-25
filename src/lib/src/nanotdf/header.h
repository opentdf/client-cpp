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

#ifndef VIRTRU_HEADER_H
#define VIRTRU_HEADER_H

#include "crypto/crypto_utils.h"
#include "resource_locator.h"
#include "ecc_mode.h"
#include "symmetric_and_payload_config.h"
#include "policy_info.h"

namespace virtru::nanotdf {

    /******************************** Header**************************
    | Section            | Minimum Length (B)  | Maximum Length (B)  |
    |--------------------|---------------------|---------------------|
    | Magic Number       | 2                   | 2                   |
    | Version            | 1                   | 1                   |
    | KAS                | 3                   | 257                 |
    | ECC Mode           | 1                   | 1                   |
    | Payload + Sig Mode | 1                   | 1                   |
    | Policy             | 3                   | 257                 |
    | Ephemeral Key      | 33                  | 67                  |
    ********************************* Header*************************/

    static const std::array<char, 3> kNanoTDFMagicStringAndVersion = {'L', '1', 'L'};

    class Header {
    public:
        /// Constructor for empty object.
        Header();

        /// Constructor the object by reading the buffer.
        /// \param bytes - The bytes with nano tdf header info.
        explicit Header(Bytes bytes);

        /// Destructors
        ~Header();

        /// Copy constructor
        Header(const Header &header);

        /// Assignment operator
        Header &operator=(const Header &header);

        /// Move copy constructor
        Header(Header &&header) noexcept;

        /// Move assignment operator
        Header &operator=(Header &&header) noexcept;

    public: /// Interface

        /// Return the magic number and version used in nano tdf.
        /// \return Bytes - The buffer containing the magic number and version.
        Bytes getMagicNumberAndVersion() const;

        /// Set the kas locator for this header object.
        /// \param kasLocator - A ResourceLocator to locate the kas.
        void setKasLocator(ResourceLocator&& kasLocator);
        void setKasLocator(const ResourceLocator& kasLocator);

        /// Return the kas locator from this header.
        /// \return ResourceLocator - A ResourceLocator to locate the kas.
        ResourceLocator getKasLocator() const;

        /// Set the ECC mode for this header object.
        /// \param eccMode - The ecc mode for the nano tdf.
        void setECCMode(ECCMode&& eccMode);
        void setECCMode(const ECCMode& eccMode);

        /// Return the ECC mode form this header object.
        /// \return ECCMode - The ecc mode for the nano tdf.
        ECCMode getECCMode() const;

        /// Set the payload config for this header object.
        /// \param SymmetricAndPayloadConfig - The payload config for the nano tdf.
        void setPayloadConfig(SymmetricAndPayloadConfig&& payloadConfig);
        void setPayloadConfig(const SymmetricAndPayloadConfig& payloadConfig);

        /// Return the payload config form this header object.
        /// \return SymmetricAndPayloadConfig - The payload config for the nano tdf.
        SymmetricAndPayloadConfig getPayloadConfig() const;

        /// Set the policy info for this header object.
        /// \param policyInfo - The policy info for the nano tdf.
        void setPolicyInfo(PolicyInfo&& policyInfo);
        void setPolicyInfo(const PolicyInfo& policyInfo);

        /// Return the policy info form this header object.
        /// \return PolicyInfo - The policy info for the nano tdf.
        PolicyInfo getPolicyInfo() const;

        /// Set the ephemeral key for this header object
        /// \param bytes - The reference to the ephemeral key.
        void setEphemeralKey(Bytes bytes);

        /// Return the reference to the data of ephemeral key.
        /// \return Bytes - The reference to the data of ephemeral key.
        Bytes getEphemeralKey() const;

        /// Get the total size required to store Header data.
        /// \return Return the total size required to store Header data.
        std::uint16_t getTotalSize() const;

        /// Write this object data into the buffer and return the amount of bytes
        /// added to the buffer.
        /// \param bytes - The buffer
        /// \return The amount of bytes added to the buffer.
        std::uint16_t writeIntoBuffer(WriteableBytes bytes) const;

    private: /// Data
        std::array<char, 3>         m_magicNumberAndVersion{kNanoTDFMagicStringAndVersion};
        ResourceLocator             m_kasLocator;
        ECCMode                     m_eccMode;
        SymmetricAndPayloadConfig   m_payloadConfig;
        PolicyInfo                  m_policyInfo;
        std::vector<gsl::byte>      m_ephemeralKey;
    };
}


#endif //VIRTRU_HEADER_H
