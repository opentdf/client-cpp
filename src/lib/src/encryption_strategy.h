/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/03.
//

#ifndef VIRTRU_ENCRYPTION_STRATEGY_H
#define VIRTRU_ENCRYPTION_STRATEGY_H

#include "key_access.h"
#include <string>
#include "nlohmann/json.hpp"
#include "manifest_data_model.h"

namespace virtru {

    /// Forward declaration
    class PolicyObject;
    class KeyAccess;

    class EncryptionStrategy {
    public:
        virtual ~EncryptionStrategy() = default;;

        /// Add KeyAccess object.
        /// \param KeyAccess - A keyAccess object.
        virtual void addKeyAccess(std::unique_ptr<KeyAccess> keyAccess) = 0;

        /// Generate and return manifest.
        /// \return - A json string holding the manifest information.
        virtual ManifestDataModel getManifest() = 0;

        /// Encrypt the data using the cipher.
        /// \param data - A buffer which contains data to be encrypted
        /// \param encryptedData - A buffer for encrypted data output
        virtual void encrypt(Bytes data, WriteableBytes& encryptedData) const = 0;
        
        /// Decrypt the data using the cipher.
        /// \param data - A buffer which contains data to be decrypted
        /// \param decryptedData - A buffer for decrypted data output
        virtual void decrypt(Bytes data, WriteableBytes& decryptedData) const = 0;
    };
}  // namespace virtru

#endif //VIRTRU_ENCRYPTION_STRATEGY_H
