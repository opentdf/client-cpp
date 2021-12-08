//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/08.
//  Copyright 2019 Virtru Corporation
//

#include "attribute_object.h"
#include "tdf_exception.h"
#include "logger.h"

#include <memory>
#include <iostream>
#include "nlohmann/json.hpp"

#include <exception>
#include <typeinfo>
#include <stdexcept>
#include <boost/exception/diagnostic_information.hpp>

namespace virtru {

    /*
     * {
     *   "attribute": "https://example.com/attr/Classification",
     *   "displayName": "classification",
     *   "isDefault": true,
     *   "pubKey" : "pem encoded public key of the attribute",
     *   "kasURL" : "https://kas.example.com/"
     * }
     */

    /// Constants
    static constexpr auto kAttribute = "attribute";
    static constexpr auto kDisplayName = "displayName";
    static constexpr auto kIsDefault = "isDefault";
    static constexpr auto kPubKey = "pubKey";
    static constexpr auto kKasURL = "kasUrl";


    /// Constructor for creating an instance of AttributeObject.
    AttributeObject::AttributeObject(std::string attribute,
                                     std::string displayName,
                                     std::string  kasPublicKey,
                                     std::string kasBaseUrl,
                                     bool isDefault) :
                                     m_attribute {std::move(attribute)},
                                     m_displayName {std::move(displayName)},
                                     m_kasPublicKey {std::move(kasPublicKey)},
                                     m_kasBaseURL {std::move(kasBaseUrl)},
                                     m_isDefault{isDefault}{
    }

    /// Constructs attributeObject instance by parsing 'attributeObjectJsonStr' json string. On error
    /// throw an virtru::Exception
    AttributeObject::AttributeObject(const std::string& attributeObjectJsonStr) {
        try {
            nlohmann::json attributeObjectJson = nlohmann::json::parse(attributeObjectJsonStr);

            // Get attribute
            m_attribute = attributeObjectJson[kAttribute];

            // Get isDefault
            m_isDefault = false;
            if (attributeObjectJson.contains(kIsDefault)) {
                m_isDefault = attributeObjectJson[kIsDefault];
            }

            // Get display name
            m_displayName = attributeObjectJson[kDisplayName];

            // Get kas public key
            m_kasPublicKey = attributeObjectJson[kPubKey];

            // Get kas base url
            m_kasBaseURL = attributeObjectJson[kKasURL];
        } catch (...) {
            ThrowException(boost::current_exception_diagnostic_information());
        }
    }

    /// Return a unique resource locator of the attribute that the EAS supports/issues.
    std::string AttributeObject::getAttribute() const {
        return m_attribute;
    }

    /// Return a human readable name of the attribute.
    std::string AttributeObject::getDisplayName() const {
        return m_displayName;
    }

    /// Return PEM encoded public key of the KAS.
    std::string AttributeObject::getKasPublicKey() const {
        return m_kasPublicKey;
    }

    /// Return base URL of the KAS that can make access control decisions for this attribute.
    std::string AttributeObject::getKasBaseUrl() const{
        return m_kasBaseURL;
    }

    /// Identifies if this attribute is a default attribute.
    bool AttributeObject::isDefault() const {
        return m_isDefault;
    }

    /// Return a json string representation of this attribute object.
    std::string AttributeObject::toJsonString(bool prettyPrint) const {
        nlohmann::json attribute;

        attribute[kAttribute] = m_attribute;
        attribute[kDisplayName] = m_displayName;
        attribute[kPubKey] = m_kasPublicKey;
        attribute[kKasURL] = m_kasBaseURL;

        // Add 'isDefault' only if it's default.
        if (m_isDefault) {
            attribute[kIsDefault] = m_isDefault;
        }

        if (prettyPrint) {
            std::ostringstream oss;
            oss << std::setw(2) << attribute << std::endl;
            return oss.str();
        } else {
            return to_string(attribute);
        }
    }

    // Provide default implementation.
    AttributeObject::~AttributeObject()  = default;
    AttributeObject::AttributeObject(const AttributeObject&) = default;
    AttributeObject& AttributeObject::operator=(const AttributeObject&) = default;
    AttributeObject::AttributeObject(AttributeObject&&) noexcept = default;
    AttributeObject& AttributeObject::operator=(AttributeObject&&) = default;

}  // namespace virtru
