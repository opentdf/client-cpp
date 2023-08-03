/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 5/17/23.
//

#ifndef VIRTRU_TDF_ASSERTION_H
#define VIRTRU_TDF_ASSERTION_H

#include <string>
#include <vector>

namespace virtru {

    enum class AssertionType {
        Handling,
        Base
    };

    enum class Scope {
        TDO,
        PAYL,
        EXPLICIT,
        Unknown
    };

    enum class AppliesToState {
        encrypted,
        unencrypted,
        Unknown
    };

    enum class StatementType {
        ReferenceStatement,
        StructuredStatement,
        StringStatement,
        Base64BinaryStatement,
        XMLBase64,
        HandlingStatement,
        String,
        Unknown
    };

    class StatementGroup {
    public:
        /// Constructor
        /// \param statementType
        StatementGroup(StatementType statementType) : m_type{statementType} {};

        /// Destructor
        ~StatementGroup() = default;

        /// Assignment operator
        StatementGroup &operator=(const StatementGroup &statementGroup) = default;

        /// Copy constructor
        StatementGroup(const StatementGroup &statementGroup) = default;

        /// Move copy constructor
        StatementGroup(StatementGroup &&statementGroup) = default;

        /// Move assignment operator
        StatementGroup &operator=(StatementGroup &&statementGroup) = default;

    public: /// Interface
        /// Set the statement type for the statement group
        /// \param statementType
        void setStatementType(StatementType statementType) {
            m_type = statementType;
        }

        /// Return the statement type for the statement group
        /// \return StatementType
        StatementType getStatementType() const {
            return m_type;
        }

        /// Set the filename for the statement group
        /// \param filename
        void setFilename(std::string filename) {
            m_filename = filename;
        }

        /// Return the filename for the statement group
        /// \return filename
        std::string getFilename() const {
            return m_filename;
        }

        /// Set the media type for the statement group
        /// \param mediaType
        void setMediaType(std::string mediaType) {
            m_mediaType = mediaType;
        }

        /// Return the media type for the statement group
        /// \return media type
        std::string getMediaType() const {
            return m_mediaType;
        }

        /// Set the uri for the statement group
        /// \param uri
        void setUri(std::string uri) {
            m_uri = uri;
        }

        /// Return the uri for the statement group
        /// \return uri
        std::string getUri() const {
            return m_uri;
        }

        /// Set the value for the statement group.
        /// \param value
        void setValue(std::string value) {
            m_value = value;
        }

        /// Return the statement value for the statement group
        /// \return statement value
        std::string getValue() const {
            return m_value;
        }

        /// Set value for the isEncrypted flag for the statement group
        /// \param isEncrypted
        void setIsEncrypted(bool isEncrypted) {
            m_isEncrypted = isEncrypted;
        }

        /// Return value of for the isEncrypted flag for the statement group
        /// \return flag
        bool getIsEncrypted() const {
            return m_isEncrypted;
        }

    private:
        StatementType m_type{StatementType::XMLBase64};
        std::string m_filename;
        std::string m_mediaType;
        std::string m_uri;
        std::string m_value;
        bool m_isEncrypted{false};
    };

    class Assertion {
    public:
        /// Constructor
        /// \param scope
        Assertion(AssertionType type, Scope scope)
        : m_assertionType{type}, m_scope{scope} {
        }

        /// Destructor
        ~Assertion() = default;

        /// Assignment operator
        Assertion &operator=(const Assertion &assertion) = default;

        /// Copy constructor
        Assertion(const Assertion &assertion) = default;

        /// Move copy constructor
        Assertion(Assertion &&assertion) = default;

        /// Move assignment operator
        Assertion &operator=(Assertion &&assertion) = default;

    public: /// Interface

        /// Return the assertion type
        /// \return assertion type
        AssertionType getAssertionType() const {
            return m_assertionType;
        }

        /// Set the scope for the assertion
        /// \param scope
        void setScope(Scope scope) {
            m_scope = scope;
        }

        /// Return the scope of the assertion
        /// \return scope
        Scope getScope() const {
            return m_scope;
        }

        /// Set the id for the assertion
        /// \param id
        void setId(std::string id) {
            m_id = id;
        }

        /// Return the id of the assertion
        /// \return id
        std::string getId() const {
            return m_id;
        }

        /// Set the type for the assertion
        /// \param type
        void setType(std::string type) {
            m_type = type;
        }

        /// Return the type of the assertion
        /// \return type
        std::string getType() const {
            return m_type;
        }

        /// Set the applied state for the assertion.
        /// \param appliesToState
        void setAppliesToState(AppliesToState appliesToState) {
            m_appliesToState = appliesToState;
        }

        /// Return the applied state of the assertion.
        /// \return applied state
        AppliesToState getAppliesToState() const {
            return m_appliesToState;
        }

        /// Set the statement group for the assertion
        /// \param statementGroup
        void setStatementGroup(StatementGroup statementGroup) {
            m_statementGroup = statementGroup;
        }

        /// Return the statement group of the assertopn
        /// \return StatementGroup
        StatementGroup getStatementGroup() const {
            return m_statementGroup;
        }

        /// Set the statement metadata for the assertion
        /// \param statementMetaData
        void setStatementMetadata(std::string statementMetaData) {
            m_statementMetadata.emplace_back(statementMetaData);
        }

        /// Return the metadata information of the assertion
        /// \return
        std::vector<std::string> getStatementMetadata() const {
            return m_statementMetadata;
        }

    private:
        AssertionType m_assertionType;
        Scope m_scope;
        AppliesToState m_appliesToState{AppliesToState::Unknown};
        std::string m_id;
        std::string m_type;
        StatementGroup m_statementGroup{StatementType::Unknown};
        std::vector<std::string> m_statementMetadata;
    };
}
#endif // VIRTRU_TDF_ASSERTION_H
