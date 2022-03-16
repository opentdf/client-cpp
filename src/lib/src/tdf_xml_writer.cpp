/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/8/21.
//

#include "libxml2_deleters.h"
#include "logger.h"
#include "tdf_constants.h"
#include "sdk_constants.h"
#include "tdf_exception.h"
#include "tdf_xml_writer.h"

#include <boost/beast/core/detail/base64.hpp>

namespace virtru {

    using namespace boost::beast::detail::base64;

    constexpr auto kXMLEncoding = "UTF-8";

    /// Constructor for TDFXMLWriter
    TDFXMLWriter::TDFXMLWriter(std::string manifestFilename, std::string payloadFileName)
        : m_manifestFilename{std::move(manifestFilename)}, m_payloadFileName{std::move(payloadFileName)} {
    }

    /// Set the payload size of the TDF
    /// \param payloadSize
    void TDFXMLWriter::setPayloadSize(int64_t payloadSize)  {
        m_binaryPayload.reserve(payloadSize);
    }

    /// Append the manifest contents to the archive.
    void TDFXMLWriter::appendManifest(std::string&& manifest) {
        m_manifest = std::move(manifest);
    }

    /// Append the manifest contents to the archive.
    void TDFXMLWriter::appendPayload(crypto::Bytes payload) {
        m_binaryPayload.insert(m_binaryPayload.end(), payload.begin(), payload.end());
    }

    /// Write the XML TDF to the output stream
    void TDFXMLWriter::writeToStream(std::ostream& outStream) {
        xmlBufferFreePtr xmlBuffer{xmlBufferCreate()};
        if (!xmlBuffer) {
            std::string errorMsg{"Fail to create XML Buffer for creating the XML TDF"};
            ThrowException(std::move(errorMsg));
        }

        // Create a new XmlWriter to write the xml with no compression.
        xmlTextWriterFreePtr writer{xmlNewTextWriterMemory(xmlBuffer.get(), 0)};
        if (!writer) {
            std::string errorMsg{"Error creating the xml writer"};
            ThrowException(std::move(errorMsg));
        }

        // Start the document with the xml default for the version, encoding UTF-8 and
        // the default for the standalone declaration.
        auto rc = xmlTextWriterStartDocument(writer.get(), nullptr, kXMLEncoding, nullptr);
        if (rc < 0) {
            std::string errorMsg{"Error creating the xml writer"};
            ThrowException(std::move(errorMsg));
        }

        // Start an element named "TrustedDataObject". Since this is the first
        // element, this will be the root element of the XML TDF
        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kEncryptionInformationElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement"};
            ThrowException(std::move(errorMsg));
        }

        auto manifestEncodedSize = encoded_size(m_manifest.size());
        std::vector<char> encodeBuffer(manifestEncodedSize);
        auto actualEncodedBufSize = encode(encodeBuffer.data(), m_manifest.data(), m_manifest.size());

        rc = xmlTextWriterWriteRawLen(writer.get(),
                                      reinterpret_cast<const xmlChar *>(encodeBuffer.data()),
                                      actualEncodedBufSize);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteRawLen"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement"};
            ThrowException(std::move(errorMsg));
        }

        // Start an element named "Base64BinaryPayload" child of "TrustedDataObject"
        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement"};
            ThrowException(std::move(errorMsg));
        }

        // Add 'mediaType' attribute to element Base64BinaryPayload
        rc = xmlTextWriterWriteAttribute(writer.get(), reinterpret_cast<const xmlChar *>(kMediaTypeAttribute),
                                         reinterpret_cast<const xmlChar *>(kTextPlainMediaType));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteAttribute"};
            ThrowException(std::move(errorMsg));
        }

        // Add 'filename' attribute to element Base64BinaryPayload
        rc = xmlTextWriterWriteAttribute(writer.get(), reinterpret_cast<const xmlChar *>(kFilenameAttribute),
                                         reinterpret_cast<const xmlChar *>(kTDFPayloadFileName));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteAttribute"};
            ThrowException(std::move(errorMsg));
        }

        // Add 'isEncrypted' attribute to element Base64BinaryPayload
        rc = xmlTextWriterWriteAttribute(writer.get(), reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute),
                                         reinterpret_cast<const xmlChar *>(kAttributeValueAsTrue));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteAttribute"};
            ThrowException(std::move(errorMsg));
        }

        encodeBuffer.resize(encoded_size(m_binaryPayload.size()));
        actualEncodedBufSize = encode(encodeBuffer.data(), m_binaryPayload.data(), m_binaryPayload.size());

        rc = xmlTextWriterWriteRawLen(writer.get(),
                                      reinterpret_cast<const xmlChar *>(encodeBuffer.data()),
                                      actualEncodedBufSize);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteRawLen"};
            ThrowException(std::move(errorMsg));
        }

        // Close the element named Base64BinaryPayload
        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement"};
            ThrowException(std::move(errorMsg));
        }

        // Close the element named TrustedDataObject
        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement"};
            ThrowException(std::move(errorMsg));
        }

        // Close the document
        rc = xmlTextWriterEndDocument(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndDocument"};
            ThrowException(std::move(errorMsg));
        }

        outStream.write(reinterpret_cast<const char *>(xmlBuffer.get()->content),
                        xmlBufferLength(xmlBuffer.get()));
    }
}
