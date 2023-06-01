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
#include <magic_enum.hpp>

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

        // Parse HandlingAssertion
        readHandlingAssertion(doc.get(), dataModel);

        // Parse default assertions
        readDefaultAssertion(doc.get(), dataModel);

        XMLCharFreePtr xmlCharBase64Payload;

        cur = cur->xmlChildrenNode;
        while (cur != nullptr) {

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
                if (mediaTypeAsXmlChar) {
                    mediaTypeFreePtr.reset(mediaTypeAsXmlChar);

                    std::string mediaTypeStr(reinterpret_cast<const char *>(mediaTypeFreePtr.get()),
                                             xmlStrlen(mediaTypeFreePtr.get()));
                    dataModel.payload.mimeType = mediaTypeStr;
                } else {
                    LogWarn("mediaType attribute is missing from the XML TDF");
                }

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
            xmlNodePtr curNodePtr, ManifestDataModel& dataModel) {

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
            xmlChar *encryptedPolicyObjectXPath = (xmlChar*) "/*[local-name(.) = 'TrustedDataObject']"
                                                             "/*[local-name(.) = 'EncryptionInformation']"
                                                             "/*[local-name(.) = 'KeyAccess']"
                                                             "/*[local-name(.) = 'WrappedPDPKey']"
                                                             "/*[local-name(.) = 'EncryptedPolicyObject']";

            XmlXPathObjectFreePtr result{ getNodeset(doc, encryptedPolicyObjectXPath) };
            if (!result) {
                std::string errorMsg{"Error EncryptedPolicyObject element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (result.get()->nodesetval->nodeNr != 1) {
                std::string errorMsg{"Error EncryptedPolicyObject element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            XmlCharFreePtr encryptedPolicy { xmlNodeListGetString(doc, result.get()->nodesetval->nodeTab[0]->xmlChildrenNode, 1) };
            std::string encryptedPolicyStr(reinterpret_cast<const char*>(encryptedPolicy.get()),
                                           xmlStrlen(encryptedPolicy.get()));
            parseEncryptedPolicyObject(encryptedPolicyStr, dataModel);
        }

        // Get tdf:algorithm attribute from tdf:EncryptionMethod
        {
            xmlChar *encryptionMethodXPath = (xmlChar*) "/*[local-name(.) = 'TrustedDataObject']"
                                                        "/*[local-name(.) = 'EncryptionInformation']"
                                                        "/*[local-name(.) = 'EncryptionMethod']";

            XmlXPathObjectFreePtr result{ getNodeset(doc, encryptionMethodXPath) };
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
                    std::string algorithmAttribute(reinterpret_cast<const char*>(attr->children->content),
                                                   xmlStrlen(attr->children->content));
                    dataModel.encryptionInformation.method.algorithm = algorithmAttribute;
                }
                attr = attr->next;
            }
        }

        // Get tdf:KeySize using XPath
        {
            xmlChar *keySizeXPath = (xmlChar*) "/*[local-name(.) = 'TrustedDataObject']"
                                               "/*[local-name(.) = 'EncryptionInformation']"
                                               "/*[local-name(.) = 'EncryptionMethod']"
                                               "/*[local-name(.) = 'KeySize']";

            XmlXPathObjectFreePtr keySizeResult{ getNodeset(doc, keySizeXPath) };
            if (!keySizeResult) {
                std::string errorMsg{"Error KeySize element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (keySizeResult.get()->nodesetval->nodeNr != 1) {
                std::string errorMsg{"Error KeySize element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            XmlCharFreePtr keySize { xmlNodeListGetString(doc, keySizeResult.get()->nodesetval->nodeTab[0]->xmlChildrenNode, 1) };
            std::string keySizeStr(reinterpret_cast<const char*>(keySize.get()),
                                   xmlStrlen(keySize.get()));

            if (keySizeStr != "32") {
                std::string errorMsg{"Error wrong key size in the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }
        }

        // Get tdf:IVParams using XPath
        {
            xmlChar *ivParamsXPath = (xmlChar*) "/*[local-name(.) = 'TrustedDataObject']"
                                                "/*[local-name(.) = 'EncryptionInformation']"
                                                "/*[local-name(.) = 'EncryptionMethod']"
                                                "/*[local-name(.) = 'IVParams']";

            XmlXPathObjectFreePtr ivParamsResult{ getNodeset(doc, ivParamsXPath) };
            if (!ivParamsResult) {
                std::string errorMsg{"Error IVParams element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (ivParamsResult.get()->nodesetval->nodeNr != 1) {
                std::string errorMsg{"Error IVParams element is missing from the XML TDF"};
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            XmlCharFreePtr ivParams { xmlNodeListGetString(doc, ivParamsResult.get()->nodesetval->nodeTab[0]->xmlChildrenNode, 1) };
            std::string ivParamsStr(reinterpret_cast<const char*>(ivParams.get()),
                                    xmlStrlen(ivParams.get()));

            dataModel.encryptionInformation.method.iv = ivParamsStr;
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

        ManifestDataModel::updateDataModelWithEncryptedPolicyObject(policyObjectStr,
                                                                    dataModel);
    }

    /// Read Handling assertions from the xml
    void TDFXMLReader::readHandlingAssertion(xmlDocPtr doc, ManifestDataModel& dataModel) {

        /*
         *     <tdf:HandlingAssertion tdf:scope="PAYL" tdf:appliesToState="encrypted">
         *       <tdf:HandlingStatement>
         *         <edh:Edh xmlns:edh="urn:us:gov:ic:edh"
         *           xmlns:usagency="urn:us:gov:ic:usagency"
         *            xmlns:icid="urn:us:gov:ic:id"
         *            xmlns:arh="urn:us:gov:ic:arh"
         *            xmlns:ism="urn:us:gov:ic:ism"
         *            xmlns:ntk="urn:us:gov:ic:ntk"
         *            usagency:CESVersion="201609"
         *            icid:DESVersion="1"
         *            edh:DESVersion="201609"
         *            arh:DESVersion="3"
         *            ism:DESVersion="201609.201707"
         *            ism:ISMCATCESVersion="201709"
         *            ntk:DESVersion="201508">
         *         <icid:Identifier>guide://999990/something</icid:Identifier>
         *         <edh:DataItemCreateDateTime>2012-05-28T15:06:00Z</edh:DataItemCreateDateTime>
         *         <edh:ResponsibleEntity edh:role="Custodian">
         *           <edh:Country>USA</edh:Country>
         *           <edh:Organization>DNI</edh:Organization>
         *         </edh:ResponsibleEntity>
         *        <arh:Security ism:compliesWith="USGov USIC"
         *                     ism:resourceElement="true"
         *                     ism:createDate="2012-05-28"
         *                     ism:classification="U"
         *                     ism:ownerProducer="USA"/>
         *        </edh:Edh>
         *     </tdf:HandlingStatement>
         *   </tdf:HandlingAssertion>
         */

        xmlChar *handlingAssertionXPath = (xmlChar *) "/*[local-name(.) = 'TrustedDataObject']"
                                                      "/*[local-name(.) = 'HandlingAssertion']";

        XmlXPathObjectFreePtr result{getNodeset(doc, handlingAssertionXPath)};
        if (!result) {
            return;
//            std::string errorMsg{"Error HandlingAssertion element is missing from the XML TDF"};
//            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        auto totalNodes = result.get()->nodesetval->nodeNr;
        for (auto index = 0; index < totalNodes; index++) {

            HandlingAssertion handlingAssertion{Scope::unknown};
            xmlNodePtr handlingAssertionNode = result.get()->nodesetval->nodeTab[index];
            if (handlingAssertionNode) {

                auto handlingStatementNode = handlingAssertionNode->xmlChildrenNode;
                if (handlingStatementNode && handlingStatementNode->type == XML_TEXT_NODE) {
                    handlingStatementNode = handlingStatementNode->next;
                }

                if (handlingStatementNode) {
                    auto edhNode = handlingStatementNode->xmlChildrenNode;
                    if (edhNode && edhNode->type == XML_TEXT_NODE) {
                        edhNode = edhNode->next;
                    }

                    // Get edh
                    if (edhNode && xmlStrEqual(edhNode->name, reinterpret_cast<const xmlChar *>(kEdhElement))) {
                        std::string handlingStatement;
                        xmlBufferFreePtr bufferFreePtr {xmlBufferCreate()};
                        xmlNodeDump(bufferFreePtr.get(), NULL, (xmlNode *)edhNode, 0, 0);
                        handlingStatement.append(reinterpret_cast<char*>(bufferFreePtr.get()->content));
                        handlingAssertion.setHandlingStatement(handlingStatement);
                    }
                }
            }

            xmlAttr *attr = result.get()->nodesetval->nodeTab[index]->properties;
            while (attr) {

                if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kScopeAttribute))) {
                    std::string scopeAttribute(reinterpret_cast<const char *>(attr->children->content),
                                               xmlStrlen(attr->children->content));

                    auto scopeAsEnum = magic_enum::enum_cast<Scope>(scopeAttribute);
                    if (scopeAsEnum.has_value()) {
                        handlingAssertion.setScope(scopeAsEnum.value());
                    }
                }

                if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kAppliesToStateAttribute))) {
                    std::string appliesToStateAttribute(reinterpret_cast<const char *>(attr->children->content),
                                                        xmlStrlen(attr->children->content));

                    auto appliesToStateAsEnum = magic_enum::enum_cast<AppliesToState>(appliesToStateAttribute);
                    if (appliesToStateAsEnum.has_value()) {
                        handlingAssertion.setAppliedState(appliesToStateAsEnum.value());
                    }
                }

                if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kIdAttribute))) {
                    std::string id;
                    id.append(reinterpret_cast<const char *>(attr->children->content),
                              xmlStrlen(attr->children->content));
                    handlingAssertion.setId(id);
                }

                attr = attr->next;
            }

            dataModel.handlingAssertions.emplace_back(handlingAssertion);
        }
    }

    /// Read default assertions from the xml
    void TDFXMLReader::readDefaultAssertion(xmlDocPtr doc, ManifestDataModel& dataModel) {
        /*
         *  <tdf:Assertion tdf:id="assertion1" tdf:scope="TDO">
         *      <tdf:StringStatement tdf:isEncrypted="false">This is the first
         *      assertion</tdf:StringStatement>
         *  </tdf:Assertion>
         *
         *  <tdf:Assertion tdf:id="assertion2" tdf:scope="TDO">
         *    <tdf:Base64BinaryStatement tdf:isEncrypted="false">VGhpcyBpcyBhIGJpbmFyeSBzdGF0ZW1lbnQ=</tdf:Base64BinaryStatement>
         *  </tdf:Assertion>
         *
         *
         *    <tdf:Assertion tdf:id="assertionId1" tdf:scope="PAYL" tdf:type="binary">
         *      <tdf:StatementMetadata tdf:appliesToState="encrypted">
         *         <edh:Edh xmlns:edh="urn:us:gov:ic:edh"
         *                  xmlns:ism="urn:us:gov:ic:ism"
         *                  xmlns:usagency="urn:us:gov:ic:usagency"
         *                  xmlns:icid="urn:us:gov:ic:id"
         *                  ism:ISMCATCESVersion="201709"
         *                  usagency:CESVersion="201609"
         *                  icid:DESVersion="1">
         *             <icid:Identifier>guide://999990/DIA-CNTRL-NO-1754-1762</icid:Identifier>
         *             <edh:DataItemCreateDateTime>2006-07-28T00:00:00Z</edh:DataItemCreateDateTime>
         *             <edh:ResponsibleEntity edh:role="Custodian">
         *             <edh:Country>USA</edh:Country>
         *             <edh:Organization>DIA</edh:Organization>
         *        </edh:ResponsibleEntity>
         *        <arh:Security xmlns:arh="urn:us:gov:ic:arh"
         *              ism:classification="U"
         *              ism:ownerProducer="USA"/>
         *        </edh:Edh>
         *      </tdf:StatementMetadata>
         *    <tdf:EncryptionInformation>
         *      <tdf:KeyAccess>
         *        <tdf:AttachedKey>
         *           <tdf:KeyValue>Jk6Jmdo7FwnbuIk/vHkjxQ==</tdf:KeyValue>
         *        </tdf:AttachedKey>
         *      </tdf:KeyAccess>
         *      <tdf:EncryptionMethod tdf:algorithm="AES">
         *        <tdf:KeySize>16</tdf:KeySize>
         *      </tdf:EncryptionMethod>
         *    </tdf:EncryptionInformation>
         *    <tdf:Base64BinaryStatement tdf:filename="binVal.xml"
         *                       tdf:isEncrypted="true"
         *                        tdf:mediaType="application/octet-stream">VGhpcyBpcyBhIHRlc3Qu</tdf:Base64BinaryStatement>
         * </tdf:Assertion>
         */

        xmlChar *assertionXPath = (xmlChar *) "/*[local-name(.) = 'TrustedDataObject']"
                                              "/*[local-name(.) = 'Assertion']";

        XmlXPathObjectFreePtr result{getNodeset(doc, assertionXPath)};
        if (!result) {
            LogInfo("Assertion element is missing from the XML TDF");
            return;
        }

        auto totalNodes = result.get()->nodesetval->nodeNr;
        for (auto index = 0; index < totalNodes; index++) {

            DefaultAssertion assertion{Scope::unknown};
            std::string statementValue{};
            xmlNodePtr assertionNode = result.get()->nodesetval->nodeTab[index];

            if (assertionNode) {

                auto statementNode = assertionNode->xmlChildrenNode;
                if (statementNode && statementNode->type == XML_TEXT_NODE) {
                    statementNode = statementNode->next;
                }

                // Handle StringStatement
                if (statementNode && xmlStrEqual(statementNode->name, reinterpret_cast<const xmlChar *>(kStringStatementElement))) {

                    StatementGroup statementGroup{StatementType::StringStatement};
                    readStatementGroup(doc, statementNode, statementGroup);

                    assertion.setStatementGroup(statementGroup);

                } else if (statementNode && xmlStrEqual(statementNode->name, reinterpret_cast<const xmlChar *>(kBase64BinaryStatementElement))) {

                    StatementGroup statementGroup{StatementType::Base64BinaryStatement};
                    readStatementGroup(doc, statementNode, statementGroup);

                    assertion.setStatementGroup(statementGroup);
                } else if (statementNode && xmlStrEqual(statementNode->name, reinterpret_cast<const xmlChar *>(kReferenceStatementElement))) {

                    StatementGroup statementGroup{StatementType::ReferenceStatement};
                    readStatementGroup(doc, statementNode, statementGroup);

                    assertion.setStatementGroup(statementGroup);
                } else if (statementNode && xmlStrEqual(statementNode->name, reinterpret_cast<const xmlChar *>(kStructuredStatementElement))) {

                    StatementGroup statementGroup{StatementType::StructuredStatement};
                    readStatementGroup(doc, statementNode, statementGroup);

                    assertion.setStatementGroup(statementGroup);
                }

            }

            xmlAttr *attr = result.get()->nodesetval->nodeTab[index]->properties;
            while (attr) {

                if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kScopeAttribute))) {
                    std::string scopeAttribute(reinterpret_cast<const char *>(attr->children->content),
                                               xmlStrlen(attr->children->content));
                    auto scopeAsEnum = magic_enum::enum_cast<Scope>(scopeAttribute);
                    if (scopeAsEnum.has_value()) {
                        assertion.setScope(scopeAsEnum.value());
                    }
                }

//                if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kAppliesToStateAttribute))) {
//                    std::string appliesToStateAttribute(reinterpret_cast<const char *>(attr->children->content),
//                                                        xmlStrlen(attr->children->content));
//                    std::cout << "appliesToState attribute" << appliesToStateAttribute << std::endl;
//                    auto appliesToStateAsEnum = magic_enum::enum_cast<AppliesToState>(appliesToStateAttribute);
//                    if (appliesToStateAsEnum.has_value()) {
//                        assertion.setAppliedState(appliesToStateAsEnum.value());
//                    }
//                }

                if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kIdAttribute))) {
                    std::string idAttribute;
                    idAttribute.append(reinterpret_cast<const char *>(attr->children->content),
                                       xmlStrlen(attr->children->content));
                    assertion.setId(idAttribute);
                }

                attr = attr->next;
            }

            dataModel.defaultAssertions.emplace_back(assertion);
        }
    }

    /// Read statement group from the assertion node
    void TDFXMLReader::readStatementGroup(xmlDocPtr doc, xmlNodePtr node, StatementGroup& statementGroup) {

        XMLCharFreePtr xmlCharStatement;
        xmlChar* statement = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
        if (statement) {
            xmlCharStatement.reset(statement);
            std::string statementValue;
            statementValue.append(reinterpret_cast<const char*>(xmlCharStatement.get()),
                                  xmlStrlen(xmlCharStatement.get()));
            statementGroup.setValue(statementValue);
        }

        xmlAttr *attr = node->properties;
        while (attr) {

            if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kUriAttribute))) {
                std::string uri(reinterpret_cast<const char*>(attr->children->content),
                                xmlStrlen(attr->children->content));
                statementGroup.setUri(uri);
            }

            if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kMediaTypeAttribute))) {
                std::string mediaType(reinterpret_cast<const char*>(attr->children->content),
                                      xmlStrlen(attr->children->content));
                statementGroup.setMediaType(mediaType);
            }

            if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kFilenameAttribute))) {
                std::string filename(reinterpret_cast<const char*>(attr->children->content),
                                     xmlStrlen(attr->children->content));
                statementGroup.setFilename(filename);
            }

            if (xmlStrEqual(attr->name, reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute))) {

                std::string isEncryptedStr(reinterpret_cast<const char*>(attr->children->content),
                                           xmlStrlen(attr->children->content));
                bool isEncryptedAsBool = false;
                if ((isEncryptedStr.compare("true") == 0)) {
                    isEncryptedAsBool = true;
                }
                statementGroup.setIsEncrypted(isEncryptedAsBool);
            }

            attr = attr->next;
        }
    }

    /// Return the nodes after evaluating the XPath
    xmlXPathObjectPtr TDFXMLReader::getNodeset(xmlDocPtr doc, xmlChar *xpath) {

        XMLXPathContextFreePtr context{xmlXPathNewContext(doc)};
        if (!context) {
            return nullptr;
        }

        XmlXPathObjectFreePtr result{ xmlXPathEvalExpression(xpath, context.get())};
        if (!result) {
            return nullptr;
        }

        if (xmlXPathNodeSetIsEmpty(result->nodesetval)){
            return nullptr;
        }

        return result.release();
    }
}