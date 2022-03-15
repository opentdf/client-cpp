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

#ifndef VIRTRU_ATTRIBUTE_OBJECT_CACHE_H
#define VIRTRU_ATTRIBUTE_OBJECT_CACHE_H

#include <unordered_map>
#include "attribute_object.h"

namespace virtru {

    /// Forward declaration
    class EntityObject;

    /// This class holds multiple attribute objects and there will be only one default attribute
    /// which can be used for constructing Key Access Object.
    class AttributeObjectsCache {
    public: /// Interface

        /// Constructor for creating an instance of AttributeObjectCache.
        AttributeObjectsCache() = default;

        /// Constructor for creating an instance of AttributeObjectCache.
        /// \param entityObject - A EntityObject containing a list of Attribute Objects as jwt
        explicit AttributeObjectsCache(const EntityObject& entityObject);

        /// Return true if the cache contains the default AttributeObject.
        /// \return - True if the cache contains the default AttributeObject.
        bool hasDefaultAttribute() const;

        /// Return the default attribute stored in the cache.
        /// \return - AttributeObject.
        /// Expection will be thrown if there is no default attribute object.
        AttributeObject getDefaultAttributeObject() const;

        /// Return true if the cache contains the AttributeObject with give attribute.
        /// \param attribute - The unique resource name for the attribute object.
        /// \return - True if the cache contains the AttributeObject with give attribute.
        bool hasAttributeObject(const std::string& attribute) const;

        /// Return an AttributeObject if the cache contains the AttributeObject with give attribute.
        /// \param attribute - The unique resource name for the attribute object.
        /// \return - AttributeObject if the cache contains the AttributeObject with give attribute,
        /// if not throw an exception.
        AttributeObject getAttributeObject(const std::string& attribute) const;

        /// Add the AttributeObject to the cache only if 'attribute' is not already
        /// in the cache
        /// \param attributeObject - The AttributeObject which needs to be added.
        void addAttributeObject(AttributeObject&& attributeObject);

        /// Delete AttributeObject from the cache if it contains the AttributeObject with the 'attribute'
        /// \param attribute - The unique resource name for the attribute object.
        /// \return - True if the cache contains the AttributeObject and delete is successfull.
        bool deleteAttributeObject(const std::string& attribute);

        /// Destructors
        ~AttributeObjectsCache();

        /// Copy constructor
        AttributeObjectsCache(const AttributeObjectsCache& attributeObject);

        /// Assignment operator
        AttributeObjectsCache& operator=(const AttributeObjectsCache& attributeObject);

        /// Move copy constructor
        AttributeObjectsCache(AttributeObjectsCache&& attributeObject);

        /// Move assignment operator
        AttributeObjectsCache& operator=(AttributeObjectsCache&& attributeObject);

    private: // Data
        // The key will 'attribute' - Also known as the "attribute url." The unique resource name
        // for the attribute represented as a case-insensitive URL string.
        std::unordered_map<std::string, AttributeObject> m_attributeObjects;
    };
}  // namespace virtru



#endif //VIRTRU_ATTRIBUTE_OBJECT_CACHE_H
