/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/22.
//

#include "key_access_object.h"
#include "tdf_exception.h"
#include "logger.h"
#include "sdk_constants.h"

#include "nlohmann/json.hpp"
#include <boost/exception/diagnostic_information.hpp>
#include <boost/algorithm/string/predicate.hpp>

namespace virtru {

    /*
     *  {
     *      "type": "wrapped",
     *      "url": "https:\/\/kas.example.com:5000",
     *      "protocol": "kas",
     *      "wrappedKey": "OqnOETpwy...ck2C1a0sECyB82uw==",
     *      "policyBinding": "BzmgoIxZzMmIF42qzbdD4Rw30GtdaRSQL2Xlfms1OPs="
     *      "encryptedMetadata": "ZoJTNW24UMhnXIif0mSnqLVCU="
     *  }
     */

    /// Constructor for creating an instance of KeyAccessObject.
    KeyAccessObject::KeyAccessObject()
        : m_keyAccessType {KeyAccessType::Remote}, m_protocol {KeyAccessProtocol::Kas} { }

    /// Set the kasUrl which points to the desired KAS deployment server.
    KeyAccessObject& KeyAccessObject::setKasUrl(const std::string& kasUrl) {
        m_kasUrl = kasUrl;
        return *this;
    }

    /// Return the key access type assigned for this object.
    KeyAccessType KeyAccessObject::getKeyAccessType() const {
        return m_keyAccessType;
    }

    /// Return the KAS deployment url string
    std::string KeyAccessObject::getKasUrl() const {
        return m_kasUrl;
    }

    /// Set the Key access type, which specifies how the key is stored.
    KeyAccessObject& KeyAccessObject::setKeyAccessType(KeyAccessType keyAccessType) {
        m_keyAccessType = keyAccessType;
        return *this;
    }

    /// Return the string representation of the key access type assigned for this object.
    std::string KeyAccessObject::getKeyAccessTypeAsStr() const {
        switch(m_keyAccessType) {
            case KeyAccessType::Remote :
                return kKeyAccessRemote;
            case KeyAccessType::Wrapped :
                return kKeyAccessWrapped;
            default:
                LogWarn("Invalid KeyAccessType - KeyAccessType::Remote is returned.");
                return kKeyAccessRemote;
        }
    }

    /// Return the key access protocol assigned for this object.
    KeyAccessProtocol KeyAccessObject::getProtocol() const {
        return m_protocol;
    }

    /// Return the string representation of the protocol assigned for this object.
    std::string KeyAccessObject::getProtocolAsStr() const {
        switch(m_protocol) {
            case KeyAccessProtocol::Kas :
                return kKasProtocol;
            default:
                LogWarn("Invalid key access protocol - KeyAccessProtocol::Kas is returned.");
                return kKasProtocol;
        }
    }

    /// Set the wrapped key(symmetric key used to encrypt the payload) in base64 format.
    KeyAccessObject& KeyAccessObject::setWrappedKey(const std::string& wrappedKey) {

        // TODO: check the wrapped key is in base64 encoding.
        m_wrappedKey = wrappedKey;
        return *this;
    }

    /// Return the wrapped key of the key access object.
    std::string KeyAccessObject::getWrappedKey() const {
        return m_wrappedKey;
    }

    /// Set base64 hash which provides cryptographic integrity on the policy object.
    KeyAccessObject& KeyAccessObject::setPolicyBindingHash(const std::string& policyBindingHash) {
        // TODO: check the wrapped key is in base64 encoding.
        m_policyBindingHash = policyBindingHash;
        return *this;
    }

    /// Return a string(base64 hash) which provides cryptographic integrity on the policy object.
    std::string KeyAccessObject::getPolicyBindingHash() const {
        return m_policyBindingHash;
    }

    /// Set metadata(base64 encoded json object) associated with the TDF, and the request. This can be
    /// any information.
    KeyAccessObject& KeyAccessObject::setEncryptedMetadata(const std::string& encryptedMetadata) {
        // TODO: check the wrapped key is in base64 encoding.
        m_encryptedMetadata = encryptedMetadata;
        return *this;
    }

    /// Return metadata(base64 encoded json object) associated with the TDF.
    std::string KeyAccessObject::getEncryptedMetadata() const {
        return m_encryptedMetadata;
    }

    /// Return a data model representation of the key access object.
    KeyAccessDataModel KeyAccessObject::getDataModel() const {

        KeyAccessDataModel keyAccessObject;
        keyAccessObject.keyType = getKeyAccessTypeAsStr();
        keyAccessObject.url = m_kasUrl;
        keyAccessObject.protocol = getProtocolAsStr();
        keyAccessObject.wrappedKey = m_wrappedKey;

        keyAccessObject.policyBinding = m_policyBindingHash;

        if (!m_encryptedMetadata.empty()) {
            keyAccessObject.encryptedMetadata = m_encryptedMetadata;
        }

        return keyAccessObject;
    }

    // Provide default implementation.
    KeyAccessObject::~KeyAccessObject()  = default;
    KeyAccessObject::KeyAccessObject(const KeyAccessObject&) = default;
    KeyAccessObject::KeyAccessObject(KeyAccessObject&&) noexcept = default;
    KeyAccessObject& KeyAccessObject::operator=(KeyAccessObject&&) = default;


    /// Constructs KeyAccessObject by parsing key access data model. On error
    /// throw an virtru::Exception

    /// Constructs KeyAccessObject by parsing key access data model. On error
    /// throw an virtru::Exception
    KeyAccessObject KeyAccessObject::createKeyAccessObjectFromDataModel(const KeyAccessDataModel &keyAccessDataModel) {

        KeyAccessObject keyAccessObject{};

        // Get key access type.
        if (keyAccessDataModel.keyType.empty()) {
            ThrowException("type not found in key access object JSON", VIRTRU_KAS_OBJ_ERROR);
        }

        std::string keyAccessKeyAsStr = keyAccessDataModel.keyType;
        if (boost::iequals(keyAccessKeyAsStr, kKeyAccessRemote)) {
            keyAccessObject.m_keyAccessType = KeyAccessType::Remote;
        } else if (boost::iequals(keyAccessKeyAsStr, kKeyAccessWrapped)) {
            keyAccessObject.m_keyAccessType = KeyAccessType::Wrapped;
        } else {
            ThrowException("Invalid key access type while parsing KeyAccessObject json string.", VIRTRU_KAS_OBJ_ERROR);
        }

        // Get kas url.
        if (keyAccessDataModel.url.empty()) {
            ThrowException("url not found in key access object JSON", VIRTRU_KAS_OBJ_ERROR);
        }
        keyAccessObject.m_kasUrl = keyAccessDataModel.url;

        // Get the protocol
        if (keyAccessDataModel.protocol.empty()) {
            ThrowException("protocol not found in key access object JSON", VIRTRU_KAS_OBJ_ERROR);
        }
        std::string protocolAsStr = keyAccessDataModel.protocol;
        if (boost::iequals(protocolAsStr, kKasProtocol)) {
            keyAccessObject.m_protocol = KeyAccessProtocol::Kas;
        } else {
            ThrowException("Invalid protocol while parsing KeyAccessObject json string.", VIRTRU_KAS_OBJ_ERROR);
        }

        if (boost::iequals(keyAccessKeyAsStr, kKeyAccessWrapped)) {
            // Get the wrapped key.
            if (keyAccessDataModel.wrappedKey.empty()) {
                ThrowException("wrappedKey not found in key access object JSON", VIRTRU_KAS_OBJ_ERROR);
            }
            keyAccessObject.m_wrappedKey = keyAccessDataModel.wrappedKey;

            // Get policy binding hash.
            if (keyAccessDataModel.policyBinding.empty()) {
                ThrowException("policyBinding not found in key access object JSON", VIRTRU_KAS_OBJ_ERROR);
            }
            keyAccessObject.m_policyBindingHash = keyAccessDataModel.policyBinding;
        } else if (boost::iequals(keyAccessKeyAsStr, kKeyAccessRemote)) {
            if (!keyAccessDataModel.wrappedKey.empty()) {
                keyAccessObject.m_wrappedKey = keyAccessDataModel.wrappedKey;
            }

            if (!keyAccessDataModel.policyBinding.empty()) {
                keyAccessObject.m_policyBindingHash = keyAccessDataModel.policyBinding;
            }
        }

        if (!keyAccessDataModel.encryptedMetadata.empty()) {
            auto encryptedMetadata = keyAccessDataModel.encryptedMetadata;
            if (!encryptedMetadata.empty()) {
                // Get the encrypted meta data.
                keyAccessObject.m_encryptedMetadata = encryptedMetadata;
            }
        }

        return keyAccessObject;
    }
}  // namespace virtru


