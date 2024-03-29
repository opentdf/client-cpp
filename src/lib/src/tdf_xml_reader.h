/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/10/21.
//

#ifndef VIRTRU_TDF_XML_READER_H
#define VIRTRU_TDF_XML_READER_H

#include <string>
#include <vector>
#include <istream>
#include "tdf_reader.h"
#include "tdf_constants.h"
#include "crypto/bytes.h"
#include "io_provider.h"
#include "tdf_archive_reader.h"
#include "tdf_xml_validator.h"
#include "libxml2_deleters.h"

namespace virtru {

    using namespace virtru::crypto;


    class TDFXMLReader : public ITDFReader {
    public:
        /// Constructor
        /// \param inputProvider -  A input provider which hold the xml data.
        TDFXMLReader(IInputProvider& inputProvider);

        /// Delete default constructor
        TDFXMLReader() = delete;

        /// Destructor
        ~TDFXMLReader() override = default;

        /// Not supported.
        TDFXMLReader(const TDFXMLReader &) = delete;
        TDFXMLReader(TDFXMLReader &&) = delete;
        TDFXMLReader & operator=(const TDFXMLReader &) = delete;
        TDFXMLReader & operator=(TDFXMLReader &&) = delete;

    public: // From ITDFReader
        /// Get the manifest data model.
        /// \return - Return the manifest data model
        ManifestDataModel getManifest() override;

        /// Read payload of length starting the index.
        /// \param index - index within data where read is to begin
        /// \param length - length of data to be retrieved starting from index
        /// \param bytes - buffer for storing the retrieved data
        void readPayload(size_t index, size_t length, WriteableBytes &bytes) override;

        /// Get the size of the payload.
        /// \return std::uint64_t - Size of the payload.
        std::uint64_t getPayloadSize() const override;

        /// Establish a validator schema to verify input against
        /// \param url - URL or file path to schema to use
        /// \return - false if the supplied schema did not load correctly
        bool setValidatorSchema(const std::string& url);

    private:
        /// Read encryption information from the xml
        /// \param doc - XML document node ptr
        /// \param curNodePtr - Current node ptr
        /// \param dataModel - Data model that will updated with encryption information.
        void readEncryptionInformation(xmlDocPtr doc, xmlNodePtr curNodePtr, ManifestDataModel& dataModel);

        /// Read Handling assertion from the xml
        /// \param doc - XML document node ptr
        /// \param dataModel - Data model that will updated with handling assertion.
        void readHandlingAssertion(xmlDocPtr doc, ManifestDataModel& dataModel);

        /// Read default assertions from the xml
        /// \param doc - XML document node ptr
        /// \param dataModel - Data model that will updated with handling assertion.
        void readDefaultAssertion(xmlDocPtr doc, ManifestDataModel& dataModel);

        /// Read statement group from the assertion node
        /// \param doc - XML document node ptr
        /// \param node = The assertion node
        /// \param statementGroup - Statement group that will updated with the assertion node.
        void readStatementGroup(xmlDocPtr doc, xmlNodePtr node, StatementGroup& statementGroup);

        /// Parse the encrypted policy object XML
        /// \param policyObjectStr - encrypted policy object as base64 string
        /// \param dataModel - Manifest data model.
        void parseEncryptedPolicyObject(const std::string& policyObjectStr, ManifestDataModel& dataModel);

        /// Return the nodes after evaluating the XPath
        /// \param doc - XML document node ptr
        /// \param xpath - XPath string
        /// \return XPathObject for retrieving the nodes
        xmlXPathObjectPtr getNodeset(xmlDocPtr doc, xmlChar *xpath);

    private: /// Data
        IInputProvider&         m_inputProvider;
        std::vector<gsl::byte>  m_binaryPayload;
        TDFXMLValidator         m_XmlValidator;
    };
}

#endif //VIRTRU_TDF_XML_READER_H
