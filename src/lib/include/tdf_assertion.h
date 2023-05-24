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
        unknown
    };

    enum class AppliesToState {
        encrypted,
        unencrypted,
        unknown
    };

    enum class StatementType {
        ReferenceStatement,
        StructuredStatement,
        StringStatement,
        Base64BinaryStatement,
        XMLBase64,
        String,
        Unknow
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

        /// Set the statement type for the assertion
        /// \param statementType
        void setStatementType(StatementType statementType) {
            m_type = statementType;
        }

        /// Set the filename for the statement group.
        /// \param filename
        void setFilename(std::string filename) {
            m_filename = filename;
        }
        /// Set the media type for the statement group.
        /// \param mediaType
        void setMediaType(std::string mediaType) {
            m_mediaType = mediaType;
        }

        /// Set the uri for the statement group.
        /// \param uri
        void setUri(std::string uri) {
            m_uri = uri;
        }

        /// Set the value for the statement group.
        /// \param value
        void setValue(std::string value) {
            m_value = value;
        }

        /// set flag for the isEncrypted flag.
        /// \param isEncrypted
        void setIsEncrypted(bool isEncrypted) {
            m_isEncrypted = isEncrypted;
        }

    public:
        StatementType m_type{StatementType::XMLBase64};
        std::string m_filename;
        std::string m_mediaType;
        std::string m_uri;
        std::string m_value;
        bool m_isEncrypted{false};
    };

    class DefaultAssertion {
    public:
        /// Constructor
        /// \param scope
        DefaultAssertion(Scope scope)
            : m_scope{scope} {}

        /// Destructor
        ~DefaultAssertion() = default;

        /// Assignment operator
        DefaultAssertion &operator=(const DefaultAssertion &assertion) = default;

        /// Copy constructor
        DefaultAssertion(const DefaultAssertion &assertion) = default;

        /// Move copy constructor
        DefaultAssertion(DefaultAssertion &&assertion) = default;

        /// Move assignment operator
        DefaultAssertion &operator=(DefaultAssertion &&assertion) = default;

    public: /// Interface
        /// Set the scope for the assertion
        /// \param scope
        void setScope(Scope scope) {
            m_scope = scope;
        }

        /// Set the id for the assertion
        /// \param id
        void setId(std::string id) {
            m_id = id;
        }

        /// Set the type for the assertion
        /// \param type
        void setType(std::string type) {
            m_type = type;
        }

        /// Set the statement group for the assertion.
        /// \param statementGroup
        void setStatementGroup(StatementGroup statementGroup) {
            m_statementGroup = statementGroup;
        }

        /// Set the statement meta fata for the assertion
        /// \param statementMetaData
        void setStatementMetaData(const std::vector<std::string>& statementMetaData) {
            m_statementMetaData = statementMetaData;
        }

    public:
        Scope m_scope;
        std::string m_id;
        std::string m_type;
        StatementGroup m_statementGroup{StatementType::Unknow};
        std::vector<std::string> m_statementMetaData;
    };

    class HandlingAssertion {
    public:
        /// Constructor
        /// \param scope
        HandlingAssertion(Scope scope)
        : m_scope{scope} {}

        /// Destructor
        ~HandlingAssertion() = default;

        /// Assignment operator
        HandlingAssertion &operator=(const HandlingAssertion &assertion) = default;

        /// Copy constructor
        HandlingAssertion(const HandlingAssertion &assertion) = default;

        /// Move copy constructor
        HandlingAssertion(HandlingAssertion &&assertion) = default;

        /// Move assignment operator
        HandlingAssertion &operator=(HandlingAssertion &&assertion) = default;

    public: /// Interface
        /// Set the scope for the assertions.
        /// \param scope
        void setScope(Scope scope) {
            m_scope = scope;
        }

        /// Set the applied state for the assertion.
        /// \param appliesToState
        void setAppliedState(AppliesToState appliesToState) {
            m_appliesToState = appliesToState;
        }

        /// Set the id for the assertion
        /// \param id
        void setId(std::string id) {
            m_id = id;
        }

        /// Set the handling statement for the assertion
        /// \param statementMetaData
        void setHandlingStatement(std::string handlingStatement) {
            m_handlingStatement = handlingStatement;
        }

    public:
        Scope m_scope;
        AppliesToState m_appliesToState;
        std::string m_id;
        std::string m_handlingStatement;
    };
}
#endif // VIRTRU_TDF_ASSERTION_H
