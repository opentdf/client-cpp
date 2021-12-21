//
//  TDF SDK
//
//  Created by Sujan Reddy on 2021/12/1
//  Copyright 2021 Virtru Corporation
//

#define BOOST_TEST_MODULE test_libxml

#include <libxml/encoding.h>
#include <boost/beast/core/detail/base64.hpp>
#include "libxml2_deleters.h"
#include "sdk_constants.h"
#include <chrono>

#include <boost/test/included/unit_test.hpp>

#define MY_ENCODING "UTF-8"
using namespace virtru;
using namespace boost::beast::detail::base64;

BOOST_AUTO_TEST_SUITE(test_libxml_suite)

    std::string plainTxtFilename{"sample.txt"};
    std::string tdfFilename{"sample_tdf.xml"};
    std::string bas64Manifest{"manfiest goes here"};
    std::string bas64Payload{"encrypted payload works here"};

    BOOST_AUTO_TEST_CASE(test_tdf_xml_encrypt) {

        xmlBufferFreePtr xmlBuffer{xmlBufferCreate()};
        if (!xmlBuffer) {
            BOOST_FAIL("Fail to create XML Buffer for creating the XML TDF");
        }

        // Create a new XmlWriter to write the xml with no compression.
        xmlTextWriterFreePtr writer{xmlNewTextWriterMemory(xmlBuffer.get(), 0)};
        if (!writer) {
            BOOST_FAIL("Error creating the xml writer");
        }

        // Start the document with the xml default for the version, encoding UTF-8 and
        // the default for the standalone declaration.
        auto rc = xmlTextWriterStartDocument(writer.get(), nullptr, MY_ENCODING, nullptr);
        if (rc < 0) {
            BOOST_FAIL("Error creating the xml writer");
        }

        // Start an element named "TrustedDataObject". Since this is the first
        // element, this will be the root element of the XML TDF
        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement));
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterStartElement");
        }

        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kEncryptionInformationElement));
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterStartElement");
        }

        rc = xmlTextWriterWriteBase64(writer.get(),
                                      bas64Manifest.c_str(),
                                      0,
                                      bas64Manifest.length());
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterWriteBase64");
        }

        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterEndElement");
        }

        // Start an element named "Base64BinaryPayload" child of "TrustedDataObject"
        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement));
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterStartElement");
        }

        // Add 'mediaType' attribute to element Base64BinaryPayload
        rc = xmlTextWriterWriteAttribute(writer.get(), reinterpret_cast<const xmlChar *>(kMediaTypeAttribute),
                                         reinterpret_cast<const xmlChar *>(kTextPlainMediaType));
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterWriteAttribute");
        }

        // Add 'filename' attribute to element Base64BinaryPayload
        rc = xmlTextWriterWriteAttribute(writer.get(), reinterpret_cast<const xmlChar *>(kFilenameAttribute),
                                         reinterpret_cast<const xmlChar *>(plainTxtFilename.c_str()));
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterWriteAttribute");
        }

        // Add 'isEncrypted' attribute to element Base64BinaryPayload
        rc = xmlTextWriterWriteAttribute(writer.get(), reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute),
                                         reinterpret_cast<const xmlChar *>(kAttributeValueAsTrue));
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterWriteAttribute");
        }

        rc = xmlTextWriterWriteBase64(writer.get(),
                                      bas64Payload.c_str(),
                                      0,
                                      bas64Payload.length());
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterWriteBase64");
        }

        // Close the element named Base64BinaryPayload
        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterEndElement");
        }

        // Close the element named TrustedDataObject
        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterEndElement");
        }

        // Close the document
        rc = xmlTextWriterEndDocument(writer.get());
        if (rc < 0) {
            BOOST_FAIL("Error at xmlTextWriterEndDocument");
        }

        // This section writes to file
        std::ofstream outfile(tdfFilename.c_str(), std::ios::out | std::ios::binary);
        outfile << xmlBuffer.get()->content;
    }

    BOOST_AUTO_TEST_CASE(test_tdf_xml_decrypt) {

        XMLDocFreePtr doc{xmlParseFile(tdfFilename.c_str())};
        if (!doc) {
            BOOST_FAIL("Error parsing the xml file");
        }

        // Get the root element(TrustedDataObject) of the XML.
        xmlNodePtr cur = xmlDocGetRootElement(doc.get());
        if (!cur) {
            BOOST_FAIL("Error - empty xml document");
        }

        if (xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement))) {
            BOOST_FAIL("Error document of the wrong type, root node != TrustedDataObject ");
        }

        XMLCharFreePtr xmlCharBase64Manifest;
        XMLCharFreePtr xmlCharBase64Payload;

        cur = cur->xmlChildrenNode;
        while (cur != nullptr) {

            // Get EncryptionInformation
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kEncryptionInformationElement))) {
                xmlChar* base64Data = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!base64Data) {
                    BOOST_FAIL("Error manifest information is missing from the XML TDF");
                    return;
                }
                xmlCharBase64Manifest.reset(base64Data);
            }

            // Get Base64BinaryPayload
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement))) {
                xmlChar* base64Data = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!base64Data) {
                    BOOST_FAIL("Error binary payload information is missing from the XML TDF");
                    return;
                }
                xmlCharBase64Payload.reset(base64Data);
            }

            cur = cur->next;
        }

        if (!xmlCharBase64Manifest) {
            BOOST_FAIL("Error manifest information is missing from the XML TDF");
        }

        if (!xmlCharBase64Payload) {
            BOOST_FAIL("Error binary payload information is missing from the XML TDF");
        }

        // Get the manifest
        {
            auto base64ManifestLength = xmlStrlen(xmlCharBase64Manifest.get());
            std::vector<std::uint8_t> manifestBuffer(decoded_size(base64ManifestLength));

            auto const decodeResult = decode(&manifestBuffer[0],
                                             reinterpret_cast<const char *>(xmlCharBase64Manifest.get()),
                                             base64ManifestLength);
            manifestBuffer.resize(decodeResult.first);
            std::string manifestStr(manifestBuffer.begin(), manifestBuffer.end());
            BOOST_TEST(manifestStr == bas64Manifest);
        }


        // Get the payload
        {
            auto base64PayloadLength = xmlStrlen(xmlCharBase64Payload.get());
            std::vector<std::uint8_t> payloadBuffer(decoded_size(base64PayloadLength));

            auto const result = decode(&payloadBuffer[0],
                                       reinterpret_cast<const char *>(xmlCharBase64Payload.get()),
                                       base64PayloadLength);
            payloadBuffer.resize(result.first);
            std::string payloadStr(payloadBuffer.begin(), payloadBuffer.end());
            BOOST_TEST(payloadStr == bas64Payload);
        }
    }

BOOST_AUTO_TEST_SUITE_END()
