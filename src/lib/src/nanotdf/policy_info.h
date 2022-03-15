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

#ifndef VIRTRU_POLICY_INFO_H
#define VIRTRU_POLICY_INFO_H

#include "crypto/crypto_utils.h"
#include "resource_locator.h"

namespace virtru::nanotdf {

    /// Forward declaration
    class ECCMode;

    using namespace virtru;
    using namespace virtru::crypto;

    /**************************Policy******************************
    | The structure of the Policy is as follows:
    |
    | Section       | Minimum Length (B)  | Maximum Length (B)  |
    |---------------|---------------------|---------------------|
    | Type Enum     | 1                   | 1                   |
    | Body          | 3                   | 257                 |
    | Binding       | 8                   | 132                 |
    **************************Policy******************************/

    class PolicyInfo {
    public: // enums

        /**************************PolicyKeyAccess******************************
        | Section                | Minimum Length (B) | Maximum Length (B)  |
        |------------------------|--------------------|---------------------|
        | Resource Locator       | 3                  | 257                 |
        | Ephemeral Public Key   | 33                 | 133                 |
        **************************PolicyKeyAccess******************************/
        /// Struct to define the policy key access data.
        struct PolicyKeyAccess {
            ResourceLocator policyKeyLocator;
            std::vector<gsl::byte> ephemeralPublicKey;
        };

    public:
        /// Constructor for empty object.
        PolicyInfo();

        /// Constructor the object by reading the buffer.
        /// \param bytes - The bytes with policy info
        /// \param eccMode - The ECC mode defines the binding.
        /// TODO: May want pass the key to decrypt the policy.
        PolicyInfo(Bytes bytes, const ECCMode& eccMode);

        /// Destructors
        ~PolicyInfo();

        /// Copy constructor
        PolicyInfo(const PolicyInfo &policyInfo);

        /// Assignment operator
        PolicyInfo &operator=(const PolicyInfo &policyInfo);

        /// Move copy constructor
        PolicyInfo(PolicyInfo &&policyInfo) noexcept;

        /// Move assignment operator
        PolicyInfo &operator=(PolicyInfo &&policyInfo) noexcept;

    public: /// Interface
        /// Return the type of the policy.
        /// \return The type of the policy.
        NanoTDFPolicyType getPolicyType() const;

        /// Update the instance with remote policy information.
        /// \param policyUrl - The url to access the remote policy.
        void setRemotePolicy(const std::string& policyUrl);

        /// Return the url of the remote policy.
        /// \return The url of the remote policy.
        std::string getRemotePolicyUrl() const;

        /// Update the instance with embedded plain text policy.
        /// \param bytes - The buffer containing the embedded plain text policy.
        void setEmbeddedPlainTextPolicy(Bytes bytes);

        /// Return the policy as plain text buffer.
        /// \return The policy as plain text buffer.
        Bytes getEmbeddedPlainTextPolicy() const;

        /// Update the instance with embedded encrypted text policy.
        /// \param bytes - The buffer containing the embedded cipher text policy.
        void setEmbeddedEncryptedTextPolicy(Bytes bytes);

        /// Return the policy as encrypted text buffer.
        /// \return The policy as encrypted text buffer.
        Bytes getEmbeddedEncryptedTextPolicy() const;

        /// Set the policy binding.
        /// \param bytes The policy binding buffer.
        void setPolicyBinding(Bytes bytes);

        /// Return the policy binding.
        /// \return The policy binding buffer.
        Bytes getPolicyBinding() const;

        /// Get the total size required to store PolicyInfo data.
        /// \return Return the total size required to store PolicyInfo data.
        std::uint16_t getTotalSize() const ;

        /// Write this object data into the buffer and return the amount of bytes
        /// added to the buffer.
        /// \param bytes - The buffer
        /// \return The amount of bytes added to the buffer.
        std::uint16_t writeIntoBuffer(WriteableBytes bytes) const;

    public: /// Static
        /// Return the string representation of policy type(logging purpose).
        /// \param policyType - The policy type
        /// \return The string representation of policy type.
        static std::string PolicyTypeAsString(NanoTDFPolicyType policyType);

    public: /// Debug information
        /// Log the information of this object as base64 data.
        static void LogContentAsBase64(const PolicyInfo& policyInfo);

    private: // Data
        /**************************EmbeddedPolicy***********************************
        | Section                       | Minimum Length (B) | Maximum Length (B)  |
        |-------------------------------|--------------------|---------------------|
        | Content Length                | 1                  | 1                   |
        | Plaintext/Ciphertext          | 2                  | 65535                 |
        | (Optional) Policy Key Access  | 36                 | 136                 |
        **************************EmbeddedPolicy***********************************/
        /// Struct to define the embedded policy key access data.
        struct EmbeddedPolicy {
            std::uint8_t policyLength;
            std::vector<gsl::byte> policyBody;
            PolicyKeyAccess policyKeyAccess;
        };

        bool                    m_hasECDSABinding{false};
        NanoTDFPolicyType      m_Type{NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED};
        std::vector<gsl::byte>  m_body;
        std::vector<gsl::byte>  m_binding;
    };
}

#endif // VIRTRU_POLICY_INFO_H
