/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/25.
//

#ifndef VIRTRU_ENTITY_OBJECT_H
#define VIRTRU_ENTITY_OBJECT_H

#include <string>
#include <vector>

namespace virtru {

    /// Forward declaration
    class AttributeObjectsCache;

    /// Detail documentation can be found here - https://developer.virtru.com/docs/entityobject
    class EntityObject {
    public: // Interface

        /// Constructor
        EntityObject();

        /// Set the userId to identify the user, such as email, that will be used to authenticate against the EAS.
        /// \param userId - A userId string to identify the user.
        /// \return - Return a reference of this instance.
        EntityObject& setUserId(const std::string& userId);

        /// Return the userId to associated with this entity object. The idea is to provide additional aliases to a user.
        /// \return - A userId string to identify the user.
        std::string getUserId() const;

        /// Set additional alias to a user.
        /// \param alias - Additional alias to a user.
        /// \return - Return a reference of this instance.
        EntityObject& setAliases(const std::string& alias);

        /// Return all the aliases of the user.
        /// \return - A vector of strings holding all the user aliases.
        std::vector<std::string> getAliases() const;

        /// Set attribute object that has been signed with the EAS private key as a JWT.
        /// \param attributeAsJwt - A attribute object string signed with the EAS private key as a JWT.
        /// \return - Return a reference of this instance.
        EntityObject& setAttributeAsJwt(const std::string& attributeAsJwt);

        /// Return all the attribute object that has been signed with the EAS private key as a JWT.
        /// \return - A vector of strings holding all the attribute object that has been signed
        /// with the EAS private key as a JWT.
        std::vector<std::string> getAttributesAsJWT() const;

        /// Set the entity's public key, in a PEM-encoded format.
        /// \param publicKey - A public-key in a PEM-encoded format string.
        /// \return - Return a reference of this instance.
        EntityObject& setPublicKey(const std::string& publicKey);

        /// Return the entity's public key, in a PEM-encoded format.
        /// \return -  A public-key in a PEM-encoded format string.
        std::string getPublicKey() const;

        /// Set the signer's public key, in a PEM-encoded format.
        /// \param publicKey - A public-key in a PEM-encoded format string.
        /// \return - Return a reference of this instance.
        EntityObject& setSignerPublicKey(const std::string& signerPublicKey);

        /// Return the signer's public key, in a PEM-encoded format.
        /// \return -  A public-key in a PEM-encoded format string.
        std::string getSignerPublicKey() const;

        /// Set the EAS certificate that has been signed with the EAS private key, as a JWT.
        /// \param cert - A EAS certificate signed with the EAS private key as a JWT.
        /// \return - Return a reference of this instance.
        EntityObject& setCert(const std::string& cert);

        /// Return the EAS certificate that has been signed with the EAS private key, as a JWT.
        /// \return - A EAS certificate signed with the EAS private key as a JWT.
        std::string getCert() const;

        /// Return a json string representation of the entity object.
        /// \param prettyPrint - If set to true, formats the json string.
        /// \return - The json string representation of this entity object.
        std::string toJsonString(bool prettyPrint = false) const;

        /// Destructor
        ~EntityObject();

        /// Copy constructor
        EntityObject(const EntityObject& entityObject);

        /// Assignment operator
        EntityObject& operator=(const EntityObject& entityObject);

        /// Move copy constructor
        EntityObject(EntityObject&& entityObject) noexcept;

        /// Move assignment operator
        EntityObject& operator=(EntityObject&& entityObject);

    public: /// static

        /// Constructs EntityObject by parsing 'entityObjectJsonStr' json string. On error
        /// throw an virtru::Exception
        /// \param entityObjectJsonStr  - Json string
        static EntityObject createEntityObjectFromJson(const std::string& entityObjectJsonStr);

    private: // Data
        friend AttributeObjectsCache;

        std::string m_userId;
        std::vector<std::string> m_aliases;
        std::vector<std::string> m_attributesAsJWT;
        std::string m_publicKey;
        std::string m_signerPublicKey;
        std::string m_cert;
    };
}  // namespace virtru

#endif // VIRTRU_ENTITY_OBJECT_H
