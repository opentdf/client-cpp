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

    /// Constructor
    TDFXMLReader::TDFXMLReader(IInputProvider& inputProvider): m_inputProvider(inputProvider) { }

    /// Get the manifest content.
    /// \return - Return the manifest as string.
    const std::string& TDFXMLReader::getManifest() {

        auto fileSize = m_inputProvider.getSize();

        std::vector<gsl::byte> xmlBuf(fileSize);
        auto bytes = toWriteableBytes(xmlBuf);
        m_inputProvider.readBytes(0, fileSize, bytes);

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
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                xmlCharBase64Manifest.reset(base64Data);
            }

            // Get Base64BinaryPayload
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement))) {
                xmlChar* base64Data = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!base64Data) {
                    std::string errorMsg{"Error binary payload information is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                xmlCharBase64Payload.reset(base64Data);
            }

            cur = cur->next;
        }

        if (!xmlCharBase64Manifest) {
            std::string errorMsg{"Error manifest information is missing from the XML TDF"};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        if (!xmlCharBase64Payload) {
            std::string errorMsg{"Error binary payload information is missing from the XML TDF"};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
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
        }

        return m_manifest;
    }

    /// Read payload of length starting the index.
    void TDFXMLReader::readPayload(size_t index, size_t length, WriteableBytes &bytes) {

        std::copy_n(m_binaryPayload.begin() + index, length,
                    bytes.begin());
    }

    /// Get the size of the payload.
    std::uint64_t TDFXMLReader::getPayloadSize() const {
        return m_binaryPayload.size();
    }
}
