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
#include "crypto/crypto_utils.h"
#include <boost/beast/core/detail/base64.hpp>
#include <iostream>

namespace virtru {

    using namespace boost::beast::detail::base64;

    /// Constructor
    TDFXMLReader::TDFXMLReader(IInputProvider& inputProvider): m_inputProvider(inputProvider) { }

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

        // Get the root element(TrustedDataCollection) of the XML.
        xmlNodePtr cur = xmlDocGetRootElement(doc.get());
        if (!cur) {
            std::string errorMsg{"Error - empty document"};
            ThrowException(std::move(errorMsg));
        }

        if (xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kTrustedDataCollectionElement))) {
            std::string errorMsg{"Error -  document of the wrong type, root node != TrustedDataCollection"};
            ThrowException(std::move(errorMsg));
        }

        cur = cur->xmlChildrenNode;
        if  (cur == nullptr) {
            std::string errorMsg{"Error - document of the wrong type, root node != TrustedDataObject"};
            ThrowException(std::move(errorMsg));
        }

        // Get the TrustedDataObject element
        if (cur->type == XML_TEXT_NODE) {
            cur = cur->next;
        }

        if (cur == nullptr || xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement))) {
            std::string errorMsg{"Error document of the wrong type, root node != TrustedDataObject"};
            ThrowException(std::move(errorMsg));
        }

        XMLCharFreePtr xmlCharBase64Payload;

        cur = cur->xmlChildrenNode;
        while (cur != nullptr) {

            // Get ReferenceValuePayload
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kTDFReferenceValuePayload))) {

                // isEncrypted attribute
                XMLCharFreePtr isEncryptedFreePtr;
                xmlChar* isEncryptedAsXmlChar = xmlGetProp(cur,
                                                         reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute));
                if (!isEncryptedAsXmlChar) {
                    std::string errorMsg{"Error - isEncrypted attribute is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                isEncryptedFreePtr.reset(isEncryptedAsXmlChar);

                std::string isEncryptedStr(reinterpret_cast<const char*>(isEncryptedFreePtr.get()),
                                         xmlStrlen(isEncryptedFreePtr.get()));
                bool isEncryptedAsBool = false;
                if ((isEncryptedStr.compare("true") == 0)) {
                    isEncryptedAsBool = true;
                }
                dataModel.payload.isEncrypted = isEncryptedAsBool;

                // mediaType attribute
                XMLCharFreePtr mediaTypeFreePtr;
                xmlChar* mediaTypeAsXmlChar = xmlGetProp(cur,
                                                           reinterpret_cast<const xmlChar *>(kMediaTypeAttribute));
                if (!mediaTypeAsXmlChar) {
                    std::string errorMsg{"Error - mediaType attribute is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                mediaTypeFreePtr.reset(mediaTypeAsXmlChar);

                std::string mediaTypeStr(reinterpret_cast<const char*>(mediaTypeFreePtr.get()),
                                           xmlStrlen(mediaTypeFreePtr.get()));
                dataModel.payload.mimeType = mediaTypeStr;
            }

            // Get EncryptionInformation
            if (xmlStrEqual(cur->name, reinterpret_cast<const xmlChar *>(kEncryptionInformationElement))) {
                readEncryptionInformation(doc.get(), cur, dataModel);
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

            SegmentInfoDataModel segmentInfo;
            segmentInfo.encryptedSegmentSize = encryptedSize;
            segmentInfo.segmentSize = payloadSize;
            dataModel.encryptionInformation.integrityInformation.segments.emplace_back(segmentInfo);
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

    /// Read encryption information from the xml
    void TDFXMLReader::readEncryptionInformation(xmlDocPtr doc,
            xmlNodePtr curNodePtr, ManifestDataModel& dataModel) {

        /*
         * 	<tdf:EncryptionInformation>
	     *	  <tdf:KeyAccess>
		 *		<tdf:WrappedPDPKey>
		 *			<tdf:KeyValue>Y4wTa8tdKqbHqun0v5w==</tdf:KeyValue>
		 *			<tdf:EncryptedPolicyObject>PD94bWwgdmVyc2lY3Q+Cg==</tdf:EncryptedPolicyObject>
		 *			<tdf:EncryptionInformation>
		 *				<tdf:KeyAccess>
		 *					<tdf:RemoteStoredKey tdf:protocol="kas" tdf:uri="http://kas.example.com:4000"/>
		 *				</tdf:KeyAccess>
		 *				<tdf:EncryptionMethod tdf:algorithm="AES">
		 *					<tdf:KeySize>32</tdf:KeySize>
		 *					<tdf:IVParams>OEOqJCS6mZsmLWJ3</tdf:IVParams>
		 *					<tdf:AuthenticationTag>B20abww4lLmNOqa43sas</tdf:AuthenticationTag>
		 *				</tdf:EncryptionMethod>
		 *			</tdf:EncryptionInformation>
		 *		</tdf:WrappedPDPKey>
		 *	  </tdf:KeyAccess>
		 *  </tdf:EncryptionInformation>
         */

        dataModel.encryptionInformation.keyAccessObjects.emplace_back(KeyAccessDataModel());

        // Get KeyAccess
        curNodePtr = curNodePtr->xmlChildrenNode;
        if (curNodePtr->type == XML_TEXT_NODE) {
            curNodePtr = curNodePtr->next;
        }

        if (curNodePtr == nullptr || !xmlStrEqual(curNodePtr->name, reinterpret_cast<const xmlChar *>(kKeyAccessElement))) {
            std::string errorMsg{"Error tdf:KeyAccess element is missing from the XML TDF"};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        // Get WrappedPDPKey
        curNodePtr = curNodePtr->xmlChildrenNode;
        if (curNodePtr->type == XML_TEXT_NODE) {
            curNodePtr = curNodePtr->next;
        }

        if (curNodePtr == nullptr || !xmlStrEqual(curNodePtr->name, reinterpret_cast<const xmlChar *>(kWrappedPDPKeyElement))) {
            std::string errorMsg{"Error tdf:WrappedPDPKey element is missing from the XML TDF"};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        curNodePtr = curNodePtr->xmlChildrenNode;
        while (curNodePtr != nullptr) {

            // Get tdf:KeyValue
            if(xmlStrEqual(curNodePtr->name, reinterpret_cast<const xmlChar *>(kKeyValueElement))) {
                XMLCharFreePtr keyValue;

                xmlChar* data = xmlNodeListGetString(doc, curNodePtr->xmlChildrenNode, 1);
                if (!data) {
                    std::string errorMsg{"Error - key value information is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                keyValue.reset(data);

                std::string keyValueStr(reinterpret_cast<const char*>(keyValue.get()), xmlStrlen(keyValue.get()));
                dataModel.encryptionInformation.keyAccessObjects[0].wrappedKey = keyValueStr;
                dataModel.encryptionInformation.keyAccessObjects[0].keyType = kKeyAccessWrapped;
            }

            // Get tdf:EncryptedPolicyObject
            if(xmlStrEqual(curNodePtr->name, reinterpret_cast<const xmlChar *>(kEncryptedPolicyObjectElement))) {
                XMLCharFreePtr keyValue;

                xmlChar* data = xmlNodeListGetString(doc, curNodePtr->xmlChildrenNode, 1);
                if (!data) {
                    std::string errorMsg{"Error - encrypted policy object information is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                keyValue.reset(data);

                std::string encryptedPolicyStr(reinterpret_cast<const char*>(keyValue.get()),
                                               xmlStrlen(keyValue.get()));
                parseEncryptedPolicyObject(encryptedPolicyStr, dataModel);

            }

            // Get tdf:EncryptionInformation
            if(xmlStrEqual(curNodePtr->name, reinterpret_cast<const xmlChar *>(kEncryptionInformationElement))) {
                readLeve2EncryptionInformation(doc, curNodePtr, dataModel);
            }

            curNodePtr = curNodePtr->next;
        }

    }

    void TDFXMLReader::parseEncryptedPolicyObject(const std::string& base64PolicyObjectStr,
                                                  ManifestDataModel& dataModel) {

        auto size = base64PolicyObjectStr.size();

        std::string policyObjectStr(size, '\0');
        auto const result = decode(policyObjectStr.data(),
                                   base64PolicyObjectStr.data(),
                                   base64PolicyObjectStr.size());
        policyObjectStr.resize(result.first);

        /*
         * <?xml version="1.0"?>
         * <EncryptedPolicyObject>
         *   <policy>eyJ1dWlkIjoiNlydHJ1LmNvbSJdfX0=</policy>
         *   <policyBinding>ZGMwNGExZjg0ODFjNDEzTJlODcwNA==</policyBinding>
         *   <encryptedMetadata>ZGMwNGExZjg0ODFjNDEzZ2VjYTVkOTJlODcwNA==</encryptedMetadata>
         * </EncryptedPolicyObject>
         */

        XMLDocFreePtr doc{xmlParseMemory(reinterpret_cast<const char *>(policyObjectStr.data()),
                                         policyObjectStr.size())};
        if (!doc) {
            std::string errorMsg{"Error - Document not parsed successfully."};
            ThrowException(std::move(errorMsg));
        }

        // Get the root element(EncryptedPolicyObject) of the XML.
        xmlNodePtr cur = xmlDocGetRootElement(doc.get());
        if (!cur) {
            std::string errorMsg{"Error - empty document"};
            ThrowException(std::move(errorMsg));
        }

        if (xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kEncryptedPolicyObject))) {
            std::string errorMsg{"Error -  document of the wrong type, root node != EncryptedPolicyObject"};
            ThrowException(std::move(errorMsg));
        }

        cur = cur->xmlChildrenNode;
        while (cur != nullptr) {

            // Get Policy
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kPolicy))) {

                XMLCharFreePtr xmlCharFreePtr;
                xmlChar* policy = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!policy) {
                    std::string errorMsg{"Error - policy  is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                xmlCharFreePtr.reset(policy);

                std::string policyStr(reinterpret_cast<const char*>(xmlCharFreePtr.get()),
                                               xmlStrlen(xmlCharFreePtr.get()));
                dataModel.encryptionInformation.policy = policyStr;
            }

            // Get policy binding
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kPolicyBinding))) {

                XMLCharFreePtr xmlCharFreePtr;
                xmlChar* policyBinding = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!policyBinding) {
                    std::string errorMsg{"Error - policy binding is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                xmlCharFreePtr.reset(policyBinding);

                std::string policyBindingStr(reinterpret_cast<const char*>(xmlCharFreePtr.get()),
                                      xmlStrlen(xmlCharFreePtr.get()));
                dataModel.encryptionInformation.keyAccessObjects[0].policyBinding = policyBindingStr;
            }

            // Get encrypted meta data
            if (!xmlStrcmp(cur->name, reinterpret_cast<const xmlChar *>(kEncryptedMetadata))) {

                XMLCharFreePtr xmlCharFreePtr;
                xmlChar* encryptedMetaData = xmlNodeListGetString(doc.get(), cur->xmlChildrenNode, 1);
                if (!encryptedMetaData) {
                    std::string errorMsg{"Error - encrypted meta data is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                xmlCharFreePtr.reset(encryptedMetaData);

                std::string encryptedMetaDataStr(reinterpret_cast<const char*>(xmlCharFreePtr.get()),
                                             xmlStrlen(xmlCharFreePtr.get()));
                dataModel.encryptionInformation.keyAccessObjects[0].encryptedMetadata = encryptedMetaDataStr;
            }

            cur = cur->next;
        }
    }

    void TDFXMLReader::readLeve2EncryptionInformation(xmlDocPtr doc,
                                                      xmlNodePtr curNodePtr,
                                                      ManifestDataModel& dataModel) {

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
                    xmlChar* protocolAsXmlChar = xmlGetProp(remoteStoredKeyNodePtr,
                                                            reinterpret_cast<const xmlChar *>(kProtocolElement));
                    if (!protocolAsXmlChar) {
                        std::string errorMsg{"Error -tdf:protocol attribute is missing from the XML TDF"};
                        ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                    }
                    protocolFreePtr.reset(protocolAsXmlChar);

                    std::string protocolStr(reinterpret_cast<const char*>(protocolFreePtr.get()),
                                                     xmlStrlen(protocolFreePtr.get()));
                    dataModel.encryptionInformation.keyAccessObjects[0].protocol = protocolStr;

                    // tdf:uri attribute
                    XMLCharFreePtr uriFreePtr;
                    xmlChar* uriAsXmlChar = xmlGetProp(remoteStoredKeyNodePtr,
                                                            reinterpret_cast<const xmlChar *>(kUriElement));
                    if (!uriAsXmlChar) {
                        std::string errorMsg{"Error -tdf:uri attribute is missing from the XML TDF"};
                        ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                    }
                    uriFreePtr.reset(uriAsXmlChar);

                    std::string uriStr(reinterpret_cast<const char*>(uriFreePtr.get()),
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
                xmlChar* algorithmAsXmlChar = xmlGetProp(curNodePtr,
                                                        reinterpret_cast<const xmlChar *>(kAlgorithmElement));
                if (!algorithmAsXmlChar) {
                    std::string errorMsg{"Error - tdf:algorithm attribute is missing from the XML TDF"};
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }
                algorithmFreePtr.reset(algorithmAsXmlChar);

                std::string algorithmStr(reinterpret_cast<const char*>(algorithmFreePtr.get()),
                                        xmlStrlen(algorithmFreePtr.get()));
                dataModel.encryptionInformation.method.algorithm = algorithmStr;


                auto nodePtr = curNodePtr->xmlChildrenNode;
                while (nodePtr != nullptr) {

                    if (!xmlStrcmp(nodePtr->name, reinterpret_cast<const xmlChar *>(kKeySizeElement))) {

                        XMLCharFreePtr xmlCharFreePtr;
                        xmlChar* keySize = xmlNodeListGetString(doc, nodePtr->xmlChildrenNode, 1);
                        if (!keySize) {
                            std::string errorMsg{"Error - key size  is missing from the XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                        xmlCharFreePtr.reset(keySize);

                        std::string keySizeStr(reinterpret_cast<const char*>(xmlCharFreePtr.get()),
                                              xmlStrlen(xmlCharFreePtr.get()));
                        auto keySizeAsInt = std::stoi( keySizeStr);
                        if (keySizeAsInt != 32) {
                            std::string errorMsg{"Error -invalid key size in XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                    }

                    if (!xmlStrcmp(nodePtr->name, reinterpret_cast<const xmlChar *>(kIVParamsElement))) {

                        XMLCharFreePtr xmlCharFreePtr;
                        xmlChar* ivParams = xmlNodeListGetString(doc, nodePtr->xmlChildrenNode, 1);
                        if (!ivParams) {
                            std::string errorMsg{"Error - iv params is missing from the XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                        xmlCharFreePtr.reset(ivParams);

                        std::string ivParamsStr(reinterpret_cast<const char*>(xmlCharFreePtr.get()),
                                               xmlStrlen(xmlCharFreePtr.get()));
                        dataModel.encryptionInformation.method.iv = ivParamsStr;
                    }

                    if (!xmlStrcmp(nodePtr->name, reinterpret_cast<const xmlChar *>(kAuthenticationTagElement))) {

                        XMLCharFreePtr xmlCharFreePtr;
                        xmlChar* authTag = xmlNodeListGetString(doc, nodePtr->xmlChildrenNode, 1);
                        if (!authTag) {
                            std::string errorMsg{"Error - authentication tag is missing from the XML TDF"};
                            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                        }
                        xmlCharFreePtr.reset(authTag);

                        std::string authTagStr(reinterpret_cast<const char*>(xmlCharFreePtr.get()),
                                                xmlStrlen(xmlCharFreePtr.get()));
                    }
                    nodePtr = nodePtr->next;
                }
            }

            curNodePtr = curNodePtr->next;
        }

    }

}