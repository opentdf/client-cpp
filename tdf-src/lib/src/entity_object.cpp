//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/25.
//  Copyright 2019 Virtru Corporation
//

#include "entity_object.h"
#include "tdf_exception.h"
#include "logger.h"
#include "sdk_constants.h"

#include <tao/json.hpp>
#include <boost/exception/diagnostic_information.hpp>

namespace virtru {

    /**
     * {
     *    "userId": "user@virtru.com",
     *    "aliases": [],
     *    "attributes": [
     *      {
     *         "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHR..."
     *      },
     *      {
     *         "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IPuQedtw5mNsJ0uDK4UdCChw..."
     *      }
     *    ],
     *    "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjG9w0B... XzNO4J38CoFz/\nwwIDAQAB\n-----END PUBLIC KEY-----",
     *    "cert": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2..."
     * }
     */

    /// Constructor
    EntityObject::EntityObject() = default;

    /// Set the userId to identify the user, such as email, that will be used to authenticate against the EAS.
    EntityObject& EntityObject::setUserId(const std::string& userId) {
        m_userId = userId;
        return *this;
    }

    /// Return the userId to associated with this entity object. The idea is to provide additional aliases to a user.
    std::string EntityObject::getUserId() const {
        return m_userId;
    }

    /// Set additional alias to a user.
    EntityObject& EntityObject::setAliases(const std::string& alias) {
        m_aliases.push_back(alias);
        return *this;
    }

    /// Return all the aliases of the user.
    std::vector<std::string> EntityObject::getAliases() const {
        return m_aliases;
    }

    /// Set attribute object that has been signed with the EAS private key as a JWT.
    EntityObject& EntityObject::setAttributeAsJwt(const std::string& attributeAsJwt) {
        m_attributesAsJWT.push_back(attributeAsJwt);
        return *this;
    }

    /// Return all the attribute object that has been signed with the EAS private key as a JWT.
    std::vector<std::string> EntityObject::getAttributesAsJWT() const {
        return m_attributesAsJWT;
    }

    /// Set the entity's public key, in a PEM-encoded format.
    EntityObject& EntityObject::setPublicKey(const std::string& publicKey) {
        m_publicKey = publicKey;
        return *this;
    }

    /// Return the entity's public key, in a PEM-encoded format.
    std::string EntityObject::getPublicKey() const {
        return m_publicKey;
    }

    /// Set the entity's public key, in a PEM-encoded format.
    EntityObject& EntityObject::setSignerPublicKey(const std::string& signerPublicKey) {
        m_signerPublicKey = signerPublicKey;
        return *this;
    }

    /// Return the signer's public key, in a PEM-encoded format.
    std::string EntityObject::getSignerPublicKey() const {
        return m_signerPublicKey;
    }

    /// Set the EAS certificate that has been signed with the EAS private key, as a JWT.
    EntityObject& EntityObject::setCert(const std::string& cert) {
        m_cert = cert;
        return *this;
    }

    /// Return the EAS certificate that has been signed with the EAS private key, as a JWT.
    std::string EntityObject::getCert() const {
        return m_cert;
    }

    /// Return a json string representation of the entity object.
    std::string EntityObject::toJsonString(bool prettyPrint) const {
        tao::json::value entityObject;

        // Add userId
        entityObject[kUserId] = m_userId;

        // Add aliases
        entityObject[kAliases] = tao::json::empty_array;
        for (auto& alias : m_aliases) {
            entityObject[kAliases].emplace_back(alias);
        }

        // Add attributes
        entityObject[kAttributes] = tao::json::empty_array;
        for (auto& attribute : m_attributesAsJWT) {
            tao::json::value attributeJwt;
            attributeJwt[kJWt] = attribute;
            entityObject[kAttributes].emplace_back(attributeJwt);
        }

        // Add public key.
        entityObject[kPublicKey] = m_publicKey;

        // Add cert.
        entityObject[kCert] = m_cert;

        // Add signer public key
        if (!m_signerPublicKey.empty()) {
            entityObject[kSignerPublicKey] = m_signerPublicKey;
        }

        if (prettyPrint) {
            return to_string(entityObject, 2);
        }
        return to_string(entityObject);

    }

    // Provide default implementation.
    EntityObject::~EntityObject()  = default;
    EntityObject::EntityObject(const EntityObject&) = default;
    EntityObject& EntityObject::operator=(const EntityObject& entityObject) = default;
    EntityObject::EntityObject(EntityObject&&) noexcept = default;
    EntityObject& EntityObject::operator=(EntityObject&&) = default;

    /// Constructs EntityObject by parsing 'entityObjectJsonStr' json string. On error
    /// throw an virtru::Exception
    EntityObject EntityObject::createEntityObjectFromJson(const std::string& entityObjectJsonStr) {
        EntityObject entityObject {};
        try {
            tao::json::value entityObjectJson = tao::json::from_string(entityObjectJsonStr);

            // Get userId.
            entityObject.m_userId =  entityObjectJson.as<std::string_view>(kUserId);

            // Get aliases
            auto& aliases = entityObjectJson[kAliases].get_array();
            for (auto& alias : aliases) {
                entityObject.m_aliases.push_back(alias.get_string());
            }

            // Get attributes
            auto& attributes = entityObjectJson[kAttributes].get_array();
            for (auto& attribute : attributes) {
                entityObject.m_attributesAsJWT.push_back(attribute.as<std::string>(kJWt));
            }

            // Get entity public key.
            entityObject.m_publicKey =  entityObjectJson.as<std::string_view>(kPublicKey);

            // Get cert.
            entityObject.m_cert =  entityObjectJson.as<std::string_view>(kCert);

            // Get signer public key.
            if(entityObjectJson[kSignerPublicKey].type() != tao::json::type::UNINITIALIZED) {
                entityObject.m_signerPublicKey = entityObjectJson.as<std::string_view>(kSignerPublicKey);
            }

        } catch (...) {
            ThrowException(boost::current_exception_diagnostic_information());
        }
        return entityObject;
    }
}  // namespace virtru
