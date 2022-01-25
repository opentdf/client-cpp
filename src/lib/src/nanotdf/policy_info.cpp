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

#include <boost/endian/conversion.hpp>

#include "tdf_exception.h"
#include "ecc_mode.h"
#include "utils.h"
#include "sdk_constants.h"
#include "policy_info.h"

namespace virtru::nanotdf {

    /// Constructor for empty object.
    PolicyInfo::PolicyInfo() = default;

    /// Constructor to update the object.
    PolicyInfo::PolicyInfo(Bytes bytes, const ECCMode& eccMode) {

        m_hasECDSABinding = eccMode.isECDSABindingEnabled();

        // Read the type of the policy.
        std::uint8_t policyType;
        std::memcpy(&policyType, bytes.data(), sizeof(policyType));
        m_Type = NanoTDFPolicyType(policyType);

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(policyType));

        // Remote policy - The body is resource locator.
        if (m_Type == NanoTDFPolicyType::REMOTE_POLICY) {

            // Create a resource locator object for remote policy url.
            ResourceLocator policyUrl{bytes};
            auto policyUrlSize = policyUrl.getTotalSize();

            // Write the resource locator to the body.
            m_body.resize(policyUrlSize);
            policyUrl.writeIntoBuffer(toWriteableBytes(m_body));

            // Adjust the bytes.
            bytes = bytes.subspan(policyUrlSize);
        } else { // Embedded Policy

            // Embedded policy layout
            // 1 - Length of the policy;
            // 2 - policy bytes itself
            // 3 - policy key access( ONLY for EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS)
            //      1 - resource locator
            //      2 - ephemeral public key, the size depends on ECC mode.

            // Read the policy size as big endian and covert to native.
            std::uint16_t policyLength;
            std::memcpy(&policyLength, bytes.data(), sizeof(policyLength));
            boost::endian::big_to_native_inplace(policyLength);

            // Adjust the bytes.
            bytes = bytes.subspan(sizeof(policyLength));

            if (m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_PLAIN_TEXT ||
                m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED) {

                // Copy the policy data.
                m_body.resize(policyLength);
                std::memcpy(m_body.data(), bytes.data(), policyLength);

                // Adjust the bytes.
                bytes = bytes.subspan(policyLength);

            } else if (m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS) {
                ThrowException("Embedded policy with key access is not supported.");
            } else {
                ThrowException("Invalid policy type.");
            }
        }

        std::uint8_t bindingBytesSize = kNanoTDFGMACLength;
        if(m_hasECDSABinding) { // ECDSA - The size of binding depends on the curve.
            bindingBytesSize = ECCMode::GetECKeySize(eccMode.getEllipticCurveType()) * 2;
        }

        m_binding.resize(bindingBytesSize);
        std::memcpy(m_binding.data(), bytes.data(), bindingBytesSize);
    }

    // Provide default implementation.
    PolicyInfo::~PolicyInfo()  = default;
    PolicyInfo::PolicyInfo(const PolicyInfo&) = default;
    PolicyInfo& PolicyInfo::operator=(const PolicyInfo&) = default;
    PolicyInfo::PolicyInfo(PolicyInfo&&) noexcept = default;
    PolicyInfo& PolicyInfo::operator=(PolicyInfo&&) noexcept = default;

    /// Return the type of the policy.
    NanoTDFPolicyType PolicyInfo::getPolicyType() const {
        return m_Type;
    }

    /// Update the instance with remote policy information.
    void PolicyInfo::setRemotePolicy(const std::string& policyUrl) {

        // Create a resource locator object for remote policy url.
        ResourceLocator remotePolicyUrl{policyUrl};

        auto size = remotePolicyUrl.getTotalSize();
        m_body.resize(size);

        // Copy the resource locator as policy body.
        remotePolicyUrl.writeIntoBuffer(toWriteableBytes(m_body));

        // Set the policy type to remote.
        m_Type = NanoTDFPolicyType::REMOTE_POLICY;
    }

    /// Return the url of the remote policy.
    std::string PolicyInfo::getRemotePolicyUrl() const {

        if (m_Type != NanoTDFPolicyType::REMOTE_POLICY) {
            ThrowException("Policy is not remote type.");
        }

        ResourceLocator policyUrl{toBytes(m_body)};
        return policyUrl.getResourceUrl();
    }

    /// Update the instance with embedded plain text policy.
    void PolicyInfo::setEmbeddedPlainTextPolicy(Bytes bytes) {

        // Update the size of the policy body.
        m_body.resize(bytes.size());

        // Copy the policy text.
        std::memcpy(m_body.data(), bytes.data(), bytes.size());

        // Set the policy type to remote.
        m_Type = NanoTDFPolicyType::EMBEDDED_POLICY_PLAIN_TEXT;
    }

    /// Return the policy as plain text buffer.
    Bytes PolicyInfo::getEmbeddedPlainTextPolicy() const {
        if (m_Type != NanoTDFPolicyType::EMBEDDED_POLICY_PLAIN_TEXT) {
            ThrowException("Policy is not embedded plain text type.");
        }

        return toBytes(m_body);
    }

    /// Update the instance with embedded encrypted text policy.
    void PolicyInfo::setEmbeddedEncryptedTextPolicy(Bytes bytes) {

        // Update the size of the policy body.
        m_body.resize(bytes.size());

        // Copy the policy text.
        std::memcpy(m_body.data(), bytes.data(), bytes.size());

        // Set the policy type to remote.
        m_Type = NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED;
    }

    /// Return the policy as encrypted text buffer.
    Bytes PolicyInfo::getEmbeddedEncryptedTextPolicy() const {

        if (m_Type != NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED) {
            ThrowException("Policy is not embedded encrypted text type.");
        }

        return toBytes(m_body);
    }

    /// Set the policy binding.
    void PolicyInfo::setPolicyBinding(Bytes bytes) {
        m_binding.resize(bytes.size());
        std::memcpy(m_binding.data(), bytes.data(), bytes.size());
    }

    /// Return the policy binding.
    Bytes PolicyInfo::getPolicyBinding() const {
        return toBytes(m_binding);
    }

    /// Get the total size required to store PolicyInfo data.
    std::uint16_t PolicyInfo::getTotalSize() const {

        std::uint16_t totalSize = 0;

        if (m_Type == NanoTDFPolicyType::REMOTE_POLICY) {
            totalSize = (sizeof(m_Type) + m_body.size() + m_binding.size());
        } else {
            if (m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_PLAIN_TEXT ||
                m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED) {

                std::uint16_t policySize =  m_body.size();
                totalSize = (sizeof(m_Type) + sizeof(policySize) + m_body.size() + m_binding.size());
            } else {
                ThrowException("Embedded policy with key access is not supported.");
            }
        }
        return totalSize;
    }

    /// Write this object data into the buffer and return the amount of bytes
    /// added to the buffer.
    std::uint16_t PolicyInfo::writeIntoBuffer(WriteableBytes bytes) const {

        if (bytes.size() < getTotalSize()) {
            ThrowException("Failed to write policy info - invalid buffer size.");
        }

        if (m_binding.empty()) {
            ThrowException("Policy binding is not set");
        }

        std::uint16_t totalBytesWritten = 0;

        // Write the policy info type.
        std::memcpy(bytes.data(), &m_Type, sizeof(m_Type));

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(m_Type));
        totalBytesWritten += sizeof(m_Type);

        // Remote policy - The body is resource locator.
        if (m_Type == NanoTDFPolicyType::REMOTE_POLICY) {

            // Write the policy in this case it's a resource locator;
            std::memcpy(bytes.data(), m_body.data(), m_body.size());

            // Adjust the bytes and total bytes written.
            bytes = bytes.subspan(m_body.size());
            totalBytesWritten += m_body.size();

        } else { // Embedded Policy

            // Embedded policy layout
            // 1 - Length of the policy;
            // 2 - policy bytes itself
            // 3 - policy key access( ONLY for EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS)
            //      1 - resource locator
            //      2 - ephemeral public key, the size depends on ECC mode.

            // convert to big endian and store into buffer.
            std::uint16_t bigEndianValue = m_body.size();
            boost::endian::native_to_big_inplace(bigEndianValue);
            std::memcpy(bytes.data(), &bigEndianValue, sizeof(bigEndianValue));

            // Adjust the bytes and total bytes written.
            bytes = bytes.subspan(sizeof(bigEndianValue));
            totalBytesWritten += sizeof(bigEndianValue);

            if (m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_PLAIN_TEXT ||
                m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED) {

                auto policySize = m_body.size();

                // Copy the policy data.
                std::memcpy(bytes.data(), m_body.data(), policySize);

                // Adjust the bytes and total bytes written.
                bytes = bytes.subspan(policySize);
                totalBytesWritten += policySize;
            } else if (m_Type == NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS) {
                ThrowException("Embedded policy with key access is not supported.");
            } else {
                ThrowException("Invalid policy type.");
            }
        }

        // Write the binding.
        std::memcpy(bytes.data() , m_binding.data(), m_binding.size());

        // Adjust the total bytes written
        totalBytesWritten += m_binding.size();

        return totalBytesWritten;
    }

    /// Return the string representation of policy type(logging purpose).
    std::string PolicyInfo::PolicyTypeAsString(NanoTDFPolicyType policyType) {
        switch (policyType) {
            case NanoTDFPolicyType::REMOTE_POLICY:
                return "Remote policy";
            case NanoTDFPolicyType::EMBEDDED_POLICY_PLAIN_TEXT:
                return "Embedded policy as plain text";
            case NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED:
                return "Embedded policy as encrypted text";
            case NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS:
            default:
                ThrowException("Unsupported policy type.");
                break;
        }
    }

    /// Log the information of this object as base64 data.
    void PolicyInfo::LogContentAsBase64(const PolicyInfo &policyInfo) {

        std::ostringstream os;

        os << "Policy Type: " << policyInfo.PolicyTypeAsString(policyInfo.getPolicyType()) << '\n'
           << "ECDSABinding is set? " << policyInfo.m_hasECDSABinding << '\n'
           << "Policy body as base64: " << base64Encode(toBytes(policyInfo.m_body)) << '\n'
           << "Policy binding as base64: " << base64Encode(toBytes(policyInfo.m_binding)) << '\n';

        LogInfo(os.str());
    }
}
