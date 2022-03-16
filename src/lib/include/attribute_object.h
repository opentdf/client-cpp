/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/08.
//

#ifndef VIRTRU_ATTRIBUTE_OBJECT_H
#define VIRTRU_ATTRIBUTE_OBJECT_H

#include <string>
#include <vector>

namespace virtru {

    /// Detail documentation can be found here - https://github.com/virtru/tdf-spec/blob/master/schema/AttributeObject.md
    class AttributeObject {
    public: /// Interface

        /// Constructor for creating an default instance of AttributeObject.
        AttributeObject() = delete;

        /// Constructor for creating an instance of AttributeObject.
        /// \param attribute - Unique resource locator of the attribute that the EAS supports/issues.
        /// \param displayName - Human readable name of the attribute.
        /// \param kasPublicKey - PEM encoded public key of the KAS that can make policy decisions for this attribute.
        /// \param kasbaseUrl - Base URL of the KAS that can make access control decisions for this attribute.
        /// \param isDefault - If "true" this flag identifies the attribute as the default attribute. If missing
        ///                    (preferred) or false then the attribute is not the default attribute.
        AttributeObject(std::string attribute,
                        std::string displayName,
                        std::string kasPublicKey,
                        std::string kasbaseUrl,
                        bool isDefault = false);

        /// Constructs attributeObject instance by parsing 'attributeObjectJsonStr' json string. On error
        /// throw an virtru::Exception
        /// \param attributeObjectJsonStr  - Json string
        explicit AttributeObject(const std::string& attributeObjectJsonStr);

        /// Return a unique resource locator of the attribute that the EAS supports/issues.
        /// \return - String of a unique resource locator of the attribute
        std::string getAttribute() const;

        /// Return a human readable name of the attribute.
        /// \return - Human readable string.
        std::string getDisplayName() const;

        /// Return PEM encoded public key of the KAS.
        /// \return - String of PEM encoded public key of the KAS.
        std::string getKasPublicKey() const;

        /// Return base URL of the KAS that can make access control decisions for this attribute.
        /// \return - Kas base url as string.
        std::string getKasBaseUrl() const;

        /// Identifies if this attribute is a default attribute.
        /// \return - true if this attribute is a default attribute.
        bool isDefault() const;

        /// Return a json string representation of this attribute object.
        /// \param prettyPrint - If set to true, formats the json string.
        /// \return - The json string representation of this attribute object.
        std::string toJsonString(bool prettyPrint = false) const;

        /// Destructors
        ~AttributeObject();

        /// Copy constructor
        AttributeObject(const AttributeObject& attributeObject);

        /// Assignment operator
        AttributeObject& operator=(const AttributeObject& attributeObject);

        /// Move copy constructor
        AttributeObject(AttributeObject&& attributeObject) noexcept;

        /// Move assignment operator
        AttributeObject& operator=(AttributeObject&& attributeObject);

    private: /// Data
        std::string m_attribute;
        std::string m_displayName;
        std::string m_kasPublicKey;
        std::string m_kasBaseURL;
        bool m_isDefault{};
    };
}  // namespace virtru

#endif //VIRTRU_ATTRIBUTE_OBJECT_H
