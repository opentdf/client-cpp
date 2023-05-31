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
#include "tdf_xml_reader.h"
#include "tdf_xml_validator.h"
#include "crypto/crypto_utils.h"
#include <boost/beast/core/detail/base64.hpp>
#include <iostream>
#include <libxml/xmlreader.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>

namespace virtru {

    using namespace boost::beast::detail::base64;

    /// Constructor
    TDFXMLReader::TDFXMLReader(IInputProvider &inputProvider) : m_inputProvider(inputProvider) {}

    /// Get the manifest data model.
    ManifestDataModel TDFXMLReader::getManifest() {

        ManifestDataModel dataModel;
        auto fileSize = m_inputProvider.getSize();

        std::vector<gsl::byte> xmlBuf(fileSize);
        auto bytes = toWriteableBytes(xmlBuf);
        m_inputProvider.readBytes(0, fileSize, bytes);

        XMLDocFreePtr doc{xmlParseMemory(reinterpret_cast<const char *>(xmlBuf.data()), xmlBuf.size())};
        if (!doc) {
            std::string errorMsg{"Error - Document not parsed successfully."};
            ThrowException(std::move(errorMsg));
        }

        bool valid = m_XmlValidator.validate(doc.get());
        if (!valid) {
            std::string errorMsg{"Error - document did not pass schema validation"};
            ThrowException(std::move(errorMsg));
        }

        // Get the root element(TrustedDataCollection) of the XML.
        xmlNodePtr cur = xmlDocGetRootElement(doc.get());
        if (!cur) {
            std::string errorMsg{"Error - empty document"};
            ThrowException(std::move(errorMsg));
        }

        if (!xmlStrEqual(cur->name, reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement))) {
            std::string errorMsg{"Root element should be tdf:TrustedDataObject"};
            ThrowException(std::move(errorMsg));
        }

        XMLCharFreePtr xmlCharBase64Payload;

        cur = cur->xmlChildrenNode;
        while (cur != nullptr) {

            // Get EncryptionInformation
            if (xmlStrEqual(cur->name, reinterpret_cast<const xmlChar *>(kEncryptionInformationElement))) {
                readEncryptionInformation(doc.get(), cur, dataModel);
            }

            // Get Base64BinaryPayload
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement))) {
                xmlChar *base64Data = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!base64Data) {
                    std::string errorMsg{"Error binary payload information is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                xmlCharBase64Payload.reset(base64Data);

                // isEncrypted attribute
                XMLCharFreePtr isEncryptedFreePtr;
                xmlChar *isEncryptedAsXmlChar = xmlGetProp(cur,
                                                           reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute));
                if (!isEncryptedAsXmlChar) {
                    std::string errorMsg{"Error - isEncrypted attribute is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                isEncryptedFreePtr.reset(isEncryptedAsXmlChar);

                std::string isEncryptedStr(reinterpret_cast<const char *>(isEncryptedFreePtr.get()),
                                           xmlStrlen(isEncryptedFreePtr.get()));
                bool isEncryptedAsBool = false;
                if ((isEncryptedStr.compare("true") == 0)) {
                    isEncryptedAsBool = true;
                }
                dataModel.payload.isEncrypted = isEncryptedAsBool;

                // mediaType attribute
                XMLCharFreePtr mediaTypeFreePtr;
                xmlChar *mediaTypeAsXmlChar = xmlGetProp(cur,
                                                         reinterpret_cast<const xmlChar *>(kMediaTypeAttribute));
                if (!mediaTypeAsXmlChar) {
                    std::string errorMsg{"Error - mediaType attribute is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                mediaTypeFreePtr.reset(mediaTypeAsXmlChar);

                std::string mediaTypeStr(reinterpret_cast<const char *>(mediaTypeFreePtr.get()),
                                         xmlStrlen(mediaTypeFreePtr.get()));
                dataModel.payload.mimeType = mediaTypeStr;
            }

            cur = cur->next;
        }

        if (!xmlCharBase64Payload) {
            std::string errorMsg{"Error binary payload information is missing from the XML TDF"};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        // Get the payload
        {
            auto base64PayloadLength = xmlStrlen(xmlCharBase64Payload.get());
            m_binaryPayload.resize(decoded_size(base64PayloadLength));

            auto const result = decode(&m_binaryPayload[0],
                                       reinterpret_cast<const char *>(xmlCharBase64Payload.get()),
                                       base64PayloadLength);
            auto encryptedSize = result.first;
            m_binaryPayload.resize(encryptedSize);
            dataModel.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault = encryptedSize;

            auto payloadSize = (encryptedSize - (kGcmIvSize + kAesBlockSize));
            dataModel.encryptionInformation.integrityInformation.segmentSizeDefault = payloadSize;

            if (dataModel.encryptionInformation.integrityInformation.segments.size() != 1) {
                ThrowException("ICTDF Only supports one segment.", VIRTRU_TDF_FORMAT_ERROR);
            }

            dataModel.encryptionInformation.integrityInformation.segments[0].encryptedSegmentSize = encryptedSize;
            dataModel.encryptionInformation.integrityInformation.segments[0].segmentSize = payloadSize;
        }

        return dataModel;
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

    /// Establish a validator schema to verify input against
    bool TDFXMLReader::setValidatorSchema(const std::string& url) {
        m_XmlValidator.setSchema(url);
        return m_XmlValidator.isSchemaValid();
    }

    /// Read encryption information from the xml
    void TDFXMLReader::readEncryptionInformation(xmlDocPtr doc,
                                                 xmlNodePtr curNodePtr, ManifestDataModel &dataModel) {

        /*
         * 	<tdf:EncryptionInformation>
	     *	  <tdf:KeyAccess>
		 *		<tdf:WrappedPDPKey>
		 *			<tdf:EncryptedPolicyObject>PD94bWwgdmVyc2lY3Q+Cg==</tdf:EncryptedPolicyObject>
         *		</tdf:WrappedPDPKey>
         *	   </tdf:KeyAccess>
         *	   <tdf:EncryptionMethod tdf:algorithm="AES">
         *		    <tdf:KeySize>32</tdf:KeySize>
		 *			<tdf:IVParams>OEOqJCS6mZsmLWJ3</tdf:IVParams>
		 *			<tdf:AuthenticationTag>B20abww4lLmNOqa43sas</tdf:AuthenticationTag>
		 *		</tdf:EncryptionMethod>
		 *  </tdf:EncryptionInformation>
         */

        // Get tdf:EncryptedPolicyObject using xPath
        {
            xmlChar *encryptedPolicyObjectXPath = (xmlChar *)"/*[local-name(.) = 'TrustedDataObject']"
                                                             "/*[local-name(.) = 'EncryptionInformation']"
                                                             "/*[local-name(.) = 'KeyAccess']"
                                                             "/*[local-name(.) = 'WrappedPDPKey']"
                                                             "/*[local-name(.) = 'EncryptedPolicyObject']";

            XmlXPathObjectFreePtr result{getNodeset(doc, encryptedPolicyObjectXPath)};
            if (!result) {
                std::string errorMsg{"Error EncryptedPolicyObject element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (result.get()->nodesetval->nodeNr != 1) {
                std::string errorMsg{"Error EncryptedPolicyObject element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            XmlCharFreePtr encryptedPolicy{xmlNodeListGetString(doc, result.get()->nodesetval->nodeTab[0]->xmlChildrenNode, 1)};
            std::string encryptedPolicyStr(reinterpret_cast<const char *>(encryptedPolicy.get()),
                                           xmlStrlen(encryptedPolicy.get()));
            parseEncryptedPolicyObject(encryptedPolicyStr, dataModel);
        }

        // Get tdf:algorithm attribute from tdf:EncryptionMethod
        {
            xmlChar *encryptionMethodXPath = (xmlChar *)"/*[local-name(.) = 'TrustedDataObject']"
                                                        "/*[local-name(.) = 'EncryptionInformation']"
                                                        "/*[local-name(.) = 'EncryptionMethod']";

            XmlXPathObjectFreePtr result{getNodeset(doc, encryptionMethodXPath)};
            if (!result) {
                std::string errorMsg{"Error EncryptionMethod element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (result.get()->nodesetval->nodeNr != 1) {
                std::string errorMsg{"Error EncryptedPolicyObject element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            xmlAttr *attr = result.get()->nodesetval->nodeTab[0]->properties;
            while (attr) {
                if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kAlgorithmAttribute))) {
                    std::string algorithmAttribute(reinterpret_cast<const char *>(attr->children->content),
                                                   xmlStrlen(attr->children->content));
                    dataModel.encryptionInformation.method.algorithm = algorithmAttribute;
                }
                attr = attr->next;
            }
        }

        // Get tdf:KeySize using XPath
        {
            xmlChar *keySizeXPath = (xmlChar *)"/*[local-name(.) = 'TrustedDataObject']"
                                               "/*[local-name(.) = 'EncryptionInformation']"
                                               "/*[local-name(.) = 'EncryptionMethod']"
                                               "/*[local-name(.) = 'KeySize']";

            XmlXPathObjectFreePtr keySizeResult{getNodeset(doc, keySizeXPath)};
            if (!keySizeResult) {
                std::string errorMsg{"Error KeySize element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (keySizeResult.get()->nodesetval->nodeNr != 1) {
                std::string errorMsg{"Error KeySize element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            XmlCharFreePtr keySize{xmlNodeListGetString(doc, keySizeResult.get()->nodesetval->nodeTab[0]->xmlChildrenNode, 1)};
            std::string keySizeStr(reinterpret_cast<const char *>(keySize.get()),
                                   xmlStrlen(keySize.get()));

            if (keySizeStr != "32") {
                std::string errorMsg{"Error wrong key size in the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }
        }

        // Get tdf:IVParams using XPath
        {
            xmlChar *ivParamsXPath = (xmlChar *)"/*[local-name(.) = 'TrustedDataObject']"
                                                "/*[local-name(.) = 'EncryptionInformation']"
                                                "/*[local-name(.) = 'EncryptionMethod']"
                                                "/*[local-name(.) = 'IVParams']";

            XmlXPathObjectFreePtr ivParamsResult{getNodeset(doc, ivParamsXPath)};
            if (!ivParamsResult) {
                std::string errorMsg{"Error IVParams element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (ivParamsResult.get()->nodesetval->nodeNr != 1) {
                std::string errorMsg{"Error IVParams element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            XmlCharFreePtr ivParams{xmlNodeListGetString(doc, ivParamsResult.get()->nodesetval->nodeTab[0]->xmlChildrenNode, 1)};
            std::string ivParamsStr(reinterpret_cast<const char *>(ivParams.get()),
                                    xmlStrlen(ivParams.get()));

            dataModel.encryptionInformation.method.iv = ivParamsStr;
        }
    }

    void TDFXMLReader::parseEncryptedPolicyObject(const std::string &base64PolicyObjectStr,
                                                  ManifestDataModel &dataModel) {

        auto size = base64PolicyObjectStr.size();

        std::string policyObjectStr(size, '\0');
        auto const result = decode(policyObjectStr.data(),
                                   base64PolicyObjectStr.data(),
                                   base64PolicyObjectStr.size());
        policyObjectStr.resize(result.first);

        ManifestDataModel::updateDataModelWithEncryptedPolicyObject(policyObjectStr,
                                                                    dataModel);
    }

    void TDFXMLReader::readLeve2EncryptionInformation(xmlDocPtr doc,
                                                      xmlNodePtr curNodePtr,
                                                      ManifestDataModel &dataModel) {

        curNodePtr = curNodePtr->xmlChildrenNode;
        while (curNodePtr != nullptr) {

            //  <tdf:RemoteStoredKey tdf:protocol="kas" tdf:uri="http://kas.example.com:4000"/>
            if (xmlStrEqual(curNodePtr->name, reinterpret_cast<const xmlChar *>(kKeyAccessElement))) {

                auto remoteStoredKeyNodePtr = curNodePtr->children;
                if (curNodePtr->type == XML_TEXT_NODE) {
                    curNodePtr = curNodePtr->next;
                }

                if (xmlStrEqual(remoteStoredKeyNodePtr->name, reinterpret_cast<const xmlChar *>(kRemoteStoredKeyElement))) {

                    // tdf:protocol attribute
                    XMLCharFreePtr protocolFreePtr;
                    xmlChar *protocolAsXmlChar = xmlGetProp(remoteStoredKeyNodePtr,
                                                            reinterpret_cast<const xmlChar *>(kProtocolElement));
                    if (!protocolAsXmlChar) {
                        std::string errorMsg{"Error -tdf:protocol attribute is missing from the XML TDF"};
                        ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                    }
                    protocolFreePtr.reset(protocolAsXmlChar);

                    std::string protocolStr(reinterpret_cast<const char *>(protocolFreePtr.get()),
                                            xmlStrlen(protocolFreePtr.get()));
                    dataModel.encryptionInformation.keyAccessObjects[0].protocol = protocolStr;

                    // tdf:uri attribute
                    XMLCharFreePtr uriFreePtr;
                    xmlChar *uriAsXmlChar = xmlGetProp(remoteStoredKeyNodePtr,
                                                       reinterpret_cast<const xmlChar *>(kUriElement));
                    if (!uriAsXmlChar) {
                        std::string errorMsg{"Error -tdf:uri attribute is missing from the XML TDF"};
                        ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                    }
                    uriFreePtr.reset(uriAsXmlChar);

                    std::string uriStr(reinterpret_cast<const char *>(uriFreePtr.get()),
                                       xmlStrlen(uriFreePtr.get()));
                    dataModel.encryptionInformation.keyAccessObjects[0].url = uriStr;
                }
            }

            /*
             * 	<tdf:EncryptionMethod tdf:algorithm="AES">
		     *	  <tdf:KeySize>32</tdf:KeySize>
		     *    <tdf:IVParams>OEOqJCS6mZsmLWJ3</tdf:IVParams>
		     *    <tdf:AuthenticationTag>B20abww4lLmNOqa43sas</tdf:AuthenticationTag>
		     *  </tdf:EncryptionMethod>
             */
            if (xmlStrEqual(curNodePtr->name, reinterpret_cast<const xmlChar *>(kEncryptionMethodElement))) {

                // tdf:algorithm attribute
                XMLCharFreePtr algorithmFreePtr;
                xmlChar *algorithmAsXmlChar = xmlGetProp(curNodePtr,
                                                         reinterpret_cast<const xmlChar *>(kAlgorithmAttribute));
                if (!algorithmAsXmlChar) {
                    std::string errorMsg{"Error - tdf:algorithm attribute is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                algorithmFreePtr.reset(algorithmAsXmlChar);

                std::string algorithmStr(reinterpret_cast<const char *>(algorithmFreePtr.get()),
                                         xmlStrlen(algorithmFreePtr.get()));
                dataModel.encryptionInformation.method.algorithm = algorithmStr;

                auto nodePtr = curNodePtr->xmlChildrenNode;
                while (nodePtr != nullptr) {

                    if (!xmlStrcmp(nodePtr->name, reinterpret_cast<const xmlChar *>(kKeySizeElement))) {

                        XMLCharFreePtr xmlCharFreePtr;
                        xmlChar *keySize = xmlNodeListGetString(doc, nodePtr->xmlChildrenNode, 1);
                        if (!keySize) {
                            std::string errorMsg{"Error - key size  is missing from the XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                        xmlCharFreePtr.reset(keySize);

                        std::string keySizeStr(reinterpret_cast<const char *>(xmlCharFreePtr.get()),
                                               xmlStrlen(xmlCharFreePtr.get()));
                        auto keySizeAsInt = std::stoi(keySizeStr);
                        if (keySizeAsInt != 32) {
                            std::string errorMsg{"Error -invalid key size in XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                    }

                    if (!xmlStrcmp(nodePtr->name, reinterpret_cast<const xmlChar *>(kIVParamsElement))) {

                        XMLCharFreePtr xmlCharFreePtr;
                        xmlChar *ivParams = xmlNodeListGetString(doc, nodePtr->xmlChildrenNode, 1);
                        if (!ivParams) {
                            std::string errorMsg{"Error - iv params is missing from the XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                        xmlCharFreePtr.reset(ivParams);

                        std::string ivParamsStr(reinterpret_cast<const char *>(xmlCharFreePtr.get()),
                                                xmlStrlen(xmlCharFreePtr.get()));
                        dataModel.encryptionInformation.method.iv = ivParamsStr;
                    }

                    if (!xmlStrcmp(nodePtr->name, reinterpret_cast<const xmlChar *>(kAuthenticationTagElement))) {

                        XMLCharFreePtr xmlCharFreePtr;
                        xmlChar *authTag = xmlNodeListGetString(doc, nodePtr->xmlChildrenNode, 1);
                        if (!authTag) {
                            std::string errorMsg{"Error - authentication tag is missing from the XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                        xmlCharFreePtr.reset(authTag);

                        std::string authTagStr(reinterpret_cast<const char *>(xmlCharFreePtr.get()),
                                               xmlStrlen(xmlCharFreePtr.get()));
                    }
                    nodePtr = nodePtr->next;
                }
            }

            curNodePtr = curNodePtr->next;
        }
    }

    xmlXPathObjectPtr TDFXMLReader::getNodeset(xmlDocPtr doc, xmlChar *xpath) {

        XMLXPathContextFreePtr context{xmlXPathNewContext(doc)};
        if (!context) {
            return nullptr;
        }

        XmlXPathObjectFreePtr result{xmlXPathEvalExpression(xpath, context.get())};
        if (!result) {
            return nullptr;
        }

        if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
            return nullptr;
        }

        return result.release();
    }
}