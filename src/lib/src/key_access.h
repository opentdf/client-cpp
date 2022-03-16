/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/09.
//

#ifndef VIRTRU_KEY_ACCESS_H
#define VIRTRU_KEY_ACCESS_H

#include "tdf_constants.h"
#include "key_access_object.h"
#include "crypto/bytes.h"
#include "policy_object.h"

#include <string>

/// Adopts 'Template Method' design pattern.
/// This class is responsible for creating an key access object.

namespace virtru {

    using namespace virtru::crypto;

    /// Base class
    class KeyAccess {
    public:
        /// Constructor
        KeyAccess(std::string kasUrl, std::string kasPublicKey,
                  PolicyObject policyObject, std::string metaData);

        /// Destructor
        virtual ~KeyAccess();

        /// Return meta data associated with this KeyAccess.
        /// \return - Meta data string.
        std::string getMetaData() const  { return m_metadata;}

    public: /// Interface.

        /// Construct the KeyAccessObject based on the 'KeyAccessType'
        /// \param wrappedKey - A symmetric wrapped key.
        /// \param encryptedMetaData - Encrypted meta data.
        /// \return KeyAccessObject - Return KeyAccessObject
        virtual KeyAccessObject construct(const WrappedKey& wrappedKey,
                                          const std::string& encryptedMetaData) = 0;

        /// Return policy information which will be used to construct the manifest.
        /// \return string - Policy information.
        virtual std::string policyForManifest() = 0;

    protected: /// Helpers

        /// Helper method to construct the KeyAccessObject
        /// \param wrappedKey - A symmetric key.
        /// \param encryptedMetaData - Encrypted meta data.
        /// \param keyAccessObject - A key access object.
        void build(const WrappedKey& wrappedKey,
                   const std::string& encryptedMetaData,
                   KeyAccessObject& keyAccessObject);

    protected:
        std::string   m_kasUrl;
        std::string   m_kasPublicKey;
        std::string   m_metadata;
        PolicyObject  m_policyObject;
    };

    /// Concrete implementation of 'wrapped' key access type.
    class WrappedKeyAccess: public KeyAccess {
    public:
        /// Constructor
        WrappedKeyAccess(const std::string& kasUrl, const std::string& kasPublicKey,
                         const PolicyObject& policyObject, const std::string& metaData = "");

        /// Destructor
        ~WrappedKeyAccess() override;

        /// Delete default constructor
        WrappedKeyAccess() = delete;

        /// Copy constructor
        WrappedKeyAccess(const WrappedKeyAccess& wrappedKeyAccess) = default;

        /// Assignment operator
        WrappedKeyAccess& operator=(const WrappedKeyAccess& wrappedKeyAccess) = default;

        /// Move copy constructor
        WrappedKeyAccess(WrappedKeyAccess&& wrappedKeyAccess)  = default;

        /// Move assignment operator
        WrappedKeyAccess& operator=(WrappedKeyAccess&& wrappedKeyAccess)  = default;

    public: /// KeyAccess.

        /// Construct the KeyAccessObject based on the 'KeyAccessType'
        /// \param wrappedKey - A symmetric wrapped key.
        /// \param encryptedMetaData - Encrypted meta data.
        /// \return KeyAccessObject - Return KeyAccessObject
        KeyAccessObject construct(const WrappedKey& wrappedKey,
                                          const std::string& encryptedMetaData) override;

        /// Return policy information which will be used to construct the manifest.
        /// \return string - Policy information.
        std::string policyForManifest() override;

    private: /// Data
        KeyAccessType m_keyAccessType {KeyAccessType::Wrapped};
     };

    /// Concrete implementation of 'remote' key access type.
    class RemoteKeyAccess: public KeyAccess {
    public:
        /// Constructor
        RemoteKeyAccess(const std::string& kasUrl, const std::string& kasPublicKey,
                        const PolicyObject& policyObject, const std::string& metaData = "");

        /// Destructor
        ~RemoteKeyAccess() override;

        /// Copy constructor
        RemoteKeyAccess(const RemoteKeyAccess& remoteKeyAccess) = default;

        /// Assignment operator
        RemoteKeyAccess& operator=(const RemoteKeyAccess& remoteKeyAccess) = default;

        /// Move copy constructor
        RemoteKeyAccess(RemoteKeyAccess&& remoteKeyAccess)  = default;

        /// Move assignment operator
        RemoteKeyAccess& operator=(RemoteKeyAccess&& remoteKeyAccess)  = default;

    public: /// KeyAccess.

        /// Construct the KeyAccessObject based on the 'KeyAccessType'
        /// \param wrappedKey - A symmetric wrapped key.
        /// \param encryptedMetaData - Encrypted meta data.
        /// \return KeyAccessObject - Return KeyAccessObject
        KeyAccessObject construct(const WrappedKey& wrappedKey,
                                          const std::string& encryptedMetaData) override;

        /// Return policy information which will be used to construct the manifest.
        /// \return string - Policy information.
        std::string policyForManifest() override;

    private: /// Data
        KeyAccessType m_keyAccessType {KeyAccessType::Remote};
    };
}  // namespace virtru



#endif //VIRTRU_KEY_ACCESS_H
