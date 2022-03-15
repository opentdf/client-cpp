/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/10/21.
//

#include "logger.h"
#include "tdf_exception.h"
#include "tdf_constants.h"
#include "sdk_constants.h"
#include "libxml2_deleters.h"
#include "tdf_xml_reader.h"
#include "crypto/crypto_utils.h"
#include <boost/beast/core/detail/base64.hpp>
#include <iostream>

namespace virtru {

    using namespace boost::beast::detail::base64;

    /// Constructor for TDFArchiveReader
    TDFXMLReader::TDFXMLReader(std::istream& inStream) : m_inStream(inStream) {
        m_inStream.clear();
        m_inStream.seekg(0, m_inStream.beg);
    }

    /// Get the manifest content.
    /// \return - Return the manifest as string.
    const std::string& TDFXMLReader::getManifest() {

        m_inStream.seekg(0, std::ios::end);
        auto fileSize = m_inStream.tellg();
        m_inStream.seekg(0, std::ios::beg);

        std::vector<char> xmlBuf((std::istreambuf_iterator<char>(m_inStream)),
                               std::istreambuf_iterator<char>());

        XMLDocFreePtr doc{xmlParseMemory(reinterpret_cast<const char *>(xmlBuf.data()), xmlBuf.size())};
        if (!doc) {
            std::string errorMsg{"Error parsing the xml file"};
            ThrowException(std::move(errorMsg));
        }

        // Get the root element(TrustedDataObject) of the XML.
        xmlNodePtr cur = xmlDocGetRootElement(doc.get());
        if (!cur) {
            std::string errorMsg{"Error - empty xml document"};
            ThrowException(std::move(errorMsg));
        }

        if (xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement))) {
            std::string errorMsg{"Error document of the wrong type, root node != TrustedDataObject"};
            ThrowException(std::move(errorMsg));
        }

        XMLCharFreePtr xmlCharBase64Manifest;
        XMLCharFreePtr xmlCharBase64Payload;

        cur = cur->xmlChildrenNode;
        while (cur != nullptr) {

            // Get EncryptionInformation
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kEncryptionInformationElement))) {
                xmlChar* base64Data = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!base64Data) {
                    std::string errorMsg{"Error manifest information is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg));
                }
                xmlCharBase64Manifest.reset(base64Data);
            }

            // Get Base64BinaryPayload
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement))) {
                xmlChar* base64Data = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!base64Data) {
                    std::string errorMsg{"Error binary payload information is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg));
                }
                xmlCharBase64Payload.reset(base64Data);
            }

            cur = cur->next;
        }

        if (!xmlCharBase64Manifest) {
            std::string errorMsg{"Error manifest information is missing from the XML TDF"};
            ThrowException(std::move(errorMsg));
        }

        if (!xmlCharBase64Payload) {
            std::string errorMsg{"Error binary payload information is missing from the XML TDF"};
            ThrowException(std::move(errorMsg));
        }

        // Get the manifest
        {
            auto base64ManifestLength = xmlStrlen(xmlCharBase64Manifest.get());
            m_manifest.resize(decoded_size(base64ManifestLength));

            auto const decodeResult = decode(&m_manifest[0],
                                             reinterpret_cast<const char *>(xmlCharBase64Manifest.get()),
                                             base64ManifestLength);
            m_manifest.resize(decodeResult.first);
        }


        // Get the payload
        {
            auto base64PayloadLength = xmlStrlen(xmlCharBase64Payload.get());
            m_binaryPayload.resize(decoded_size(base64PayloadLength));

            auto const result = decode(&m_binaryPayload[0],
                                       reinterpret_cast<const char *>(xmlCharBase64Payload.get()),
                                       base64PayloadLength);
            m_binaryPayload.resize(result.first);
            m_payloadLeftToRead = m_binaryPayload.size();
        }

        return m_manifest;
    }

    /// Read the payload contents into the buffer.
    /// The size of buffer could be less than requested size.
    /// \param buffer - WriteableBytes
    void TDFXMLReader::readPayload(WriteableBytes& buffer){

        std::size_t sizeToRead;
        if (buffer.size() > m_payloadLeftToRead) {
            sizeToRead = m_payloadLeftToRead;
        } else {
            sizeToRead = buffer.size();
            m_payloadLeftToRead -= buffer.size();
        }

        // Copy the payload buffer contents into encrypt buffer without the IV padding.
        std::copy_n(m_binaryPayload.begin() + m_payloadStartIndex, sizeToRead,
                buffer.begin());

        m_payloadStartIndex += sizeToRead;
        buffer = buffer.first(sizeToRead);
    }

    /// Get the size of the payload.
    /// \return std::uint64_t - Size of the payload.
    std::int64_t TDFXMLReader::getPayloadSize() const {
        return m_binaryPayload.size();
    }
}
