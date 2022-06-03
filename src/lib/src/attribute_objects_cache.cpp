/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/05/22.
//

#include <jwt-cpp/jwt.h>

#include "tdf_exception.h"
#include "logger.h"
#include "entity_object.h"
#include "crypto/crypto_utils.h"
#include "attribute_objects_cache.h"

namespace virtru {

    using namespace virtru::crypto;

    /// Constructor for creating an instance of AttributeObjectCache.
    AttributeObjectsCache::AttributeObjectsCache(const EntityObject& entityObject) {

        for (auto& attributeObj : entityObject.m_attributesAsJWT) {

            auto jwtToken = jwt::decode(attributeObj);
            AttributeObject attributeObject{jwtToken.get_payload()};

            addAttributeObject(std::move(attributeObject));
        }
    }

    /// Return true if the cache contains the default AttributeObject.
    bool AttributeObjectsCache::hasDefaultAttribute() const {

        if(m_attributeObjects.empty()) {
            return false;
        }

        for (const auto& [attribute, attributeObj] : m_attributeObjects) {
            if (attributeObj.isDefault()) {
                return true;
            }
        }

        return false;
    }


    /// Return the default attribute stored in the cache.
    AttributeObject AttributeObjectsCache::getDefaultAttributeObject() const {

        if(m_attributeObjects.empty()) {
            ThrowException("Attribute objects cache is empty!", VIRTRU_ATTR_OBJ_ERROR);
        }

        for (const auto& [attribute, attributeObj] : m_attributeObjects) {
            if (attributeObj.isDefault()) {
                return attributeObj;
            }
        }

        ThrowException("Default attribute object doesn't exists", VIRTRU_TDF_FORMAT_ERROR);
        return {"", "", "", ""};
    }

    /// Return true if the cache contains the AttributeObject with give attribute.
    bool AttributeObjectsCache::hasAttributeObject(const std::string& attribute) const {

        if(m_attributeObjects.empty()) {
            return false;
        }

        std::string attributeCopy{attribute};
        std::transform(attributeCopy.begin(), attributeCopy.end(), attributeCopy.begin(), ::tolower);

        const auto& entry = m_attributeObjects.find(attributeCopy);
        return entry != m_attributeObjects.end();
    }

    /// Return an AttributeObject if the cache contains the AttributeObject with give attribute.
    AttributeObject AttributeObjectsCache::getAttributeObject(const std::string& attribute) const {

        if(m_attributeObjects.empty()) {
            ThrowException("Attribute objects cache is empty!", VIRTRU_ATTR_OBJ_ERROR);
        }

        std::string attributeCopy{attribute};
        std::transform(attributeCopy.begin(), attributeCopy.end(), attributeCopy.begin(), ::tolower);

        const auto& entry = m_attributeObjects.find(attributeCopy);
        if (entry == m_attributeObjects.end()) {
            ThrowException(attribute + " - not found in attribute objects cache.", VIRTRU_ATTR_OBJ_ERROR);
        }

        return entry->second;
    }

    /// Add the AttributeObject to the cache only if 'attribute' is not already
    /// in the cache.
    void AttributeObjectsCache::addAttributeObject(AttributeObject&& attributeObject) {

        // Store the 'attribute' as lower case.
        auto attribute =  attributeObject.getAttribute();
        std::transform(attribute.begin(), attribute.end(), attribute.begin(), ::tolower);

        const auto& entry = m_attributeObjects.find(attribute);
        if (entry == m_attributeObjects.end()) {
            m_attributeObjects.insert({attribute, attributeObject});
        }
    }

    /// Delete AttributeObject from the cache if it contains the AttributeObject with the 'attribute'
    bool AttributeObjectsCache::deleteAttributeObject(const std::string& attribute) {

        // There is should be only one element if it exists.
        return (m_attributeObjects.erase(attribute) == 1);
    }

    // Provide default implementation.
    AttributeObjectsCache::~AttributeObjectsCache()  = default;
    AttributeObjectsCache::AttributeObjectsCache(const AttributeObjectsCache&) = default;
    AttributeObjectsCache& AttributeObjectsCache::operator=(const AttributeObjectsCache&) = default;
    AttributeObjectsCache::AttributeObjectsCache(AttributeObjectsCache&&) = default;
    AttributeObjectsCache& AttributeObjectsCache::operator=(AttributeObjectsCache&&) = default;
}  // namespace virtru

