/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/8/21.
//

#ifndef VIRTRU_TDF_XML_WRITER_H
#define VIRTRU_TDF_XML_WRITER_H

#include <string>
#include <vector>
#include <unordered_map>
#include "tdf_writer.h"
#include "tdf_constants.h"
#include "crypto/bytes.h"
#include "io_provider.h"
#include "libxml2_deleters.h"
#include "tdf_archive_writer.h"
#include "tdf_xml_validator.h"

namespace virtru {

    using namespace virtru::crypto;
    using XMLAttributesNamesAndValues = std::unordered_map<std::string, std::string>;

    class TDFXMLWriter : public ITDFWriter {
    public:
        /// Constructor
        /// \param outputProvider - The ictdf data will write to the output provider.
        TDFXMLWriter(IOutputProvider& outputProvider);

        /// Delete default constructor
        TDFXMLWriter() = delete;

        /// Destructor
        ~TDFXMLWriter() override = default;

        /// Not supported.
        TDFXMLWriter(const TDFXMLWriter &) = delete;
        TDFXMLWriter(TDFXMLWriter &&) = delete;
        TDFXMLWriter & operator=(const TDFXMLWriter &) = delete;
        TDFXMLWriter & operator=(TDFXMLWriter &&) = delete;

    public: // From ITDFWriter
        /// Set the payload size of the TDF
        /// \param payloadSize
        void setPayloadSize(int64_t payloadSize) override;

        /// Append the manifest contents to the XML output source.
        /// \param manifestDataModel - Data model containing the manifest data.
        void appendManifest(ManifestDataModel manifestDataModel) override;

        /// Append the payload contents to the XML output source.
        /// \param payload - encrypted payload.
        void appendPayload(Bytes payload) override;

        /// Finalize archive entry.
        void finish() override;

        /// Establish a validator schema to verify input against
        /// \param url - URL or file path to schema to use
        /// \return - false if the supplied schema did not load correctly
        bool setValidatorSchema(const std::string& url);

    private:
        /// Add 'tdf:EncryptionInformation' element.
        /// \param rootNode - The root node
        /// \param ns - The namespace to be applied to all the child elements.
        void addEncryptionInformationElement(xmlNodePtr rootNode, xmlNsPtr ns);

        /// Add 'tdf:HandlingAssertion' element.
        /// \param writer - xml text writer object
        void addHandlingAssertionElement(xmlTextWriterPtr writer);

        /// Add 'Base64BinaryPayload' element.
        /// \param rootNode - The root node
        /// \param ns - The namespace to be applied to all the child elements.
        void addPayloadElement(xmlNodePtr rootNode, xmlNsPtr ns);

        /// Create XML element and xmlTextWriter
        /// \param writer - xml text writer object
        /// \param elementName - Element name
        /// \param elementValue - Element value
        /// \param attrubutesNameAndValues  - Dictionary of attributes names and values
        void createElement(xmlTextWriterPtr writer,
                           const std::string& elementName,
                           const std::string& elementValue,
                           XMLAttributesNamesAndValues xmlAttributesNamesAndValues);

    private: /// Data
        ManifestDataModel       m_manifestDataModel;
        std::vector<gsl::byte>  m_binaryPayload;
        IOutputProvider&        m_outputProvider;
        TDFXMLValidator         m_XmlValidatorPtr;
    };
}



#endif //VIRTRU_TDF_XML_WRITER_H
