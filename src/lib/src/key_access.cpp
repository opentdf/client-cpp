/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/09.
//

#include "key_access.h"
#include "crypto/asym_encryption.h"
#include "crypto/bytes.h"
#include "crypto/crypto_utils.h"
#include "sdk_constants.h"

#include "nlohmann/json.hpp"
#include <iostream>
#include <vector>

namespace virtru {

    using namespace virtru::crypto;

    ///
    /// Base class - KeyAccess
    ///

    /// Constructor
    KeyAccess::KeyAccess(std::string kasUrl, std::string kasPublicKey,
                         PolicyObject policyObject, std::string metadata)
                         : m_kasUrl{std::move(kasUrl)},
                         m_kasPublicKey{std::move(kasPublicKey)},
                         m_metadata{std::move(metadata)},
                         m_policyObject{std::move(policyObject)} {
    }

    /// Destructor
    KeyAccess::~KeyAccess() = default;

    /// Helper method to construct the KeyAccessObject.
    void KeyAccess::build(const WrappedKey& wrappedKey,
                          const std::string& encryptedMetaData,
                          KeyAccessObject& keyAccessObject) {

        keyAccessObject.setKasUrl(m_kasUrl);

        // Add 'wrapped' key to key access object.
        auto encoder = AsymEncryption::create(m_kasPublicKey);
        std::vector<gsl::byte> outBuffer(encoder->getOutBufferSize());
        auto writeableBytes = toWriteableBytes(outBuffer);
        encoder->encrypt(toBytes(wrappedKey), writeableBytes);
        keyAccessObject.setWrappedKey(base64Encode(writeableBytes));
        
        // Add 'policyBinding'
        auto base64PolicyStr = base64Encode(m_policyObject.toJsonString());
        
        auto policyBinding = hexHmacSha256(toBytes(base64PolicyStr), wrappedKey);
        keyAccessObject.setPolicyBindingHash(base64Encode(policyBinding));

        keyAccessObject.setEncryptedMetadata(base64Encode(encryptedMetaData));
    }

    ///
    /// Concrete implementation - WrappedKeyAccess.
    ///

    /// Constructor
    WrappedKeyAccess::WrappedKeyAccess(const std::string& kasUrl,
                                       const std::string& kasPublicKey,
                                       const PolicyObject& policyObject,
                                       const std::string& metadata)
                                       : KeyAccess(kasUrl, kasPublicKey, policyObject, metadata){
    }

    /// Destructor
    WrappedKeyAccess::~WrappedKeyAccess() = default;

    /// Construct the KeyAccessObject based on the wrapped key type.
    KeyAccessObject WrappedKeyAccess::construct(const WrappedKey& wrappedKey,
                                                const std::string& encryptedMetaData) {

        auto keyAccessObject = KeyAccessObject{};

        keyAccessObject.setKeyAccessType(m_keyAccessType);
        build(wrappedKey, encryptedMetaData, keyAccessObject);

        return keyAccessObject;
    }

    /// Return policy information which will be used to construct the manifest.
    std::string WrappedKeyAccess::policyForManifest() {
        return base64Encode(m_policyObject.toJsonString());
    }

    ///
    /// Concrete implementation - WrappedKeyAccess.
    ///

    /// Constructor
    RemoteKeyAccess::RemoteKeyAccess(const std::string& kasUrl,
                                     const std::string& kasPublicKey,
                                     const PolicyObject& policyObject,
                                     const std::string& metadata)
                                     : KeyAccess(kasUrl, kasPublicKey, policyObject, metadata) {
    }

    /// Destructor
    RemoteKeyAccess::~RemoteKeyAccess() = default;

    /// Construct the KeyAccessObject based on the remote key type.
    KeyAccessObject RemoteKeyAccess::construct(const WrappedKey& wrappedKey,
                                               const std::string& encryptedMetaData) {

        auto keyAccessObject = KeyAccessObject{};

        keyAccessObject.setKeyAccessType(m_keyAccessType);
        build(wrappedKey, encryptedMetaData, keyAccessObject);
        
        return keyAccessObject;
    }


    /// Return policy information which will be used to construct the manifest.
    std::string RemoteKeyAccess::policyForManifest() {

        nlohmann::json policyForManifest;
        policyForManifest[kUid] = m_policyObject.getUuid();

        return base64Encode(to_string(policyForManifest));
    }

} // namespace virtru
