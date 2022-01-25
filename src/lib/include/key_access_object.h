/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/22.
//

#ifndef VIRTRU_KEY_ACCESS_OBJECT_H
#define VIRTRU_KEY_ACCESS_OBJECT_H

#include <string>
#include "tdf_constants.h"

namespace virtru {

    enum class KeyAccessProtocol {
        Kas
    };

    enum class PolicyBindingAlgorithm {
        HS256
    };

    /// Detail documentation can be found here - https://developer.virtru.com/docs/keyaccessobject
    class KeyAccessObject {
    public:

        /// Constructor for creating an instance of KeyAccessObject.
        /// \param kasUrl - A url pointing to the desired KAS deployment
        /// \param keyAccessType - Key access type which specifies how the key is stored(default is 'Remote').
        KeyAccessObject();

        /// Set the kasUrl which points to the desired KAS deployment server.
        /// \param kasUrl - A url pointing to the desired KAS deployment
        /// \return - Return a reference of this instance.
        KeyAccessObject& setKasUrl(const std::string& kasUrl);

        /// Return the KAS deployment url string
        /// \return - A url string pointing to the desired KAS deployment.
        std::string getKasUrl() const;

        /// Set the Key access type, which specifies how the key is stored.
        /// \param keyAccessType - Key access type which specifies how the key is stored
        /// \return - Return a reference of this instance.
        KeyAccessObject& setKeyAccessType(KeyAccessType keyAccessType);

        /// Return the key access type assigned for this object.
        /// \return - KeyAccessType
        KeyAccessType getKeyAccessType() const;

        /// Return the string representation of the key access type assigned for this object.
        /// \return - A string representation of the key access type assigned for this object.
        std::string getKeyAccessTypeAsStr() const;

        /// Return the key access protocol assigned for this object.
        /// \return - KeyAccessProtocol
        KeyAccessProtocol getProtocol() const;

        /// Return the string representation of the protocol assigned for this object.
        /// \return - A string representation of the protocol assigned for this object.
        std::string getProtocolAsStr() const;

        /// Set the wrapped key(symmetric key used to encrypt the payload) in base64 format.
        /// This wrapped key is encrypted with KAS public key.
        /// \param wrappedKey
        /// \return - Return a reference of this instance.
        /// NOTE: throws exception if the format is not base64.
        KeyAccessObject& setWrappedKey(const std::string& wrappedKey);

        /// Return the wrapped key of the key access object.
        /// \return - Base64 encoding string of the wrapped key.
        std::string getWrappedKey() const;

        /// Set base64 hash which provides cryptographic integrity on the policy object.
        /// \param policyBindingHash - A base64 hash of of HMAC(POLICY,KEY).
        /// \return - Return a reference of this instance.
        /// NOTE: throws exception if the format is not base64.
        KeyAccessObject& setPolicyBindingHash(const std::string& policyBindingHash);

        /// Return a string(base64 hash) which provides cryptographic integrity on the policy object.
        /// \return - A base64 hash of of HMAC(POLICY,KEY).
        std::string getPolicyBindingHash() const;

        /// Set metadata(base64 encoded json object) associated with the TDF, and the request. This can be
        /// any information.
        /// \param encryptedMetadata - A metadata(base64 encoded json object) associated with the TDF.
        /// \return - - Return a reference of this instance.
        /// NOTE: throws exception if the format is not base64.
        KeyAccessObject& setEncryptedMetadata(const std::string& encryptedMetadata);

        /// Return metadata(base64 encoded json object) associated with the TDF.
        /// \return - Return Base64 encoding string of the meta data.
        std::string getEncryptedMetadata() const;

        /// Return a json string representation of the key access object
        /// \param prettyPrint - If set to true, formats the json string.
        /// \return - The json string representation of this key access object.
        std::string toJsonString(bool prettyPrint = false) const;

        /// Destructor
        ~KeyAccessObject();

        /// Copy constructor
        KeyAccessObject(const KeyAccessObject& keyAccessObject);

        /// Copy assignment operator
        KeyAccessObject& operator=(const KeyAccessObject& keyAccessObject);

        /// Move copy constructor
        KeyAccessObject(KeyAccessObject&& keyAccessObject) noexcept;

        /// Move assignment operator
        KeyAccessObject& operator=(KeyAccessObject&& keyAccessObject);

    public: /// static

        /// Constructs KeyAccessObject by parsing 'keyAccessObjectStr' json string. On error
        /// throw an virtru::Exception
        /// \param keyAccessObjectStr  - Json string
        static KeyAccessObject createKeyAccessObjectFromJson(const std::string& keyAccessObjectJsonStr);

    private: /// Data
        KeyAccessType m_keyAccessType;
        KeyAccessProtocol m_protocol;
        std::string m_kasUrl;
        std::string m_wrappedKey;
        std::string m_policyBindingHash;
        std::string m_encryptedMetadata;
    };
}  // namespace virtru

#endif // VIRTRU_KEY_ACCESS_OBJECT_H
