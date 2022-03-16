/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/02/28.
//

#ifndef VIRTRU_POLICY_OBJECT_H
#define VIRTRU_POLICY_OBJECT_H

#include "attribute_object.h"

#include <string>
#include <vector>
#include <set>

namespace virtru {

    /// Detail documentation can be found here - https://developer.virtru.com/docs/policy-object
    class PolicyObject {
    public: /// Interface

        /// Constructor for creating an instance of PolicyObject.
        PolicyObject();

        /// Add dissem(user/entity) to this policy object.
        /// \param dissem - The dissem
        /// \return - Return a reference of this instance.
        PolicyObject& addDissem(const std::string& dissem);

        /// Add attribute object to this policy object.
        /// \param attributeObject  - The attribute object
        /// \return - Return a reference of this instance.
        PolicyObject& addAttributeObject(const AttributeObject& attributeObject);

        /// Return the UUID of this policy object.
        /// \return - The string object of UUID
        std::string getUuid() const;

        /// Return the set of all the dissems of this policy object.
        /// \return - The set object holding dissems.
        std::set<std::string> getDissems() const;

        /// Return the vector of all the attribute objects of this policy object.
        /// \return - The vector object holding attribute objects.
        std::vector<AttributeObject> getAttributeObjects() const;

        /// Return a json string representation of this policy object.
        /// \param prettyPrint - If set to true, formats the json string.
        /// \return - The json string representation of this policy object.
        std::string toJsonString(bool prettyPrint = false) const;

        /// Destructors
        ~PolicyObject();

        /// Assignment operator
        PolicyObject& operator=(const PolicyObject& policyObject);

        /// Copy constructor
        PolicyObject(const PolicyObject& policyObject);

        /// Move copy constructor
        PolicyObject(PolicyObject && policyObject);

        /// Move assignment operator
        PolicyObject& operator=(PolicyObject && policyObject);

    public: // static
        /// Constructs PolicyObject by parsing 'policyObjectStr' json string. On error
        /// throw an virtru::Exception
        /// \param policyObjectJsonStr - Json string
        /// \return The PolicyObject
        static PolicyObject CreatePolicyObjectFromJson(const std::string& policyObjectJsonStr);

        /// Crete PolicyObject by copying the data(not unique identifier)
        /// \param policyObject - The PolicyObject from which data will be copied from
        /// \return The new PolicyObject with same data
        static PolicyObject CopyDataFromPolicyObject(const PolicyObject& policyObject);

    private:
        /// Data
        std::string m_uuid;
        std::vector<AttributeObject> m_attributeObjects;

        // TODO: Address duplicate and other encoding issues.
        std::set<std::string> m_dissems;
    };
}  // namespace virtru


#endif //VIRTRU_POLICY_OBJECT_H
