/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/8/21.
//

#include <iostream>
#include "libxml2_deleters.h"
#include "logger.h"
#include "tdf_constants.h"
#include "sdk_constants.h"
#include "tdf_exception.h"
#include "tdf_xml_writer.h"
#include "tdf_xml_validator.h"

#include <magic_enum.hpp>
#include <boost/beast/core/detail/base64.hpp>

namespace virtru {

    using namespace boost::beast::detail::base64;
    using namespace virtru::crypto;

    constexpr auto kXMLEncoding = "UTF-8";
    constexpr auto kICTDFVersion = "1.0";
    constexpr auto kTDFNameSpaceHref = "urn:us:gov:ic:tdf";
    constexpr auto kTDFPrefix = "tdf";
    constexpr auto kXMLHref = "http://www.w3.org/2001/XMLSchema-instance";
    constexpr auto kXSIPrefix = "xsi";

    /// Constructor for TDFXMLWriter
    TDFXMLWriter::TDFXMLWriter(IOutputProvider& outputProvider)
            : m_outputProvider(outputProvider){
    }

    /// Set the payload size of the TDF
    /// \param payloadSize
    void TDFXMLWriter::setPayloadSize(int64_t payloadSize)  {
        m_binaryPayload.reserve(payloadSize);
    }

    /// Append the manifest contents to the XML output source.
    void TDFXMLWriter::appendManifest(ManifestDataModel manifestDataModel) {
        m_manifestDataModel = manifestDataModel;
    }

    /// Append the manifest contents to the archive.
    void TDFXMLWriter::appendPayload(crypto::Bytes payload) {
        m_binaryPayload.insert(m_binaryPayload.end(), payload.begin(), payload.end());
    }


    /// Add 'tdf:EncryptionInformation' element.
    void TDFXMLWriter::addEncryptionInformationElement(xmlNodePtr rootNode, xmlNsPtr ns) {

        /*
         * <tdf:EncryptionInformation>
         *   <tdf:KeyAccess>
         *      <tdf:WrappedPDPKey>
         *      <tdf:KeyValue>YBkqvsiDnyDfw5JQzux2S2IaiClhsojZuLYYHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==</tdf:KeyValue>
         *      <tdf:EncryptedPolicyObject>2S2IaiClhsojZuLYYHiAw7hN...</tdf:EncryptedPolicyObject>
         *        <tdf:EncryptionInformation>
         *          <tdf:KeyAccess>
         *            <tdf:RemoteStoredKey tdf:protocol="KAS" tdf:uri="http://kas.example.com:4000">
         *            </tdf:RemoteStoredKey>
         *          </tdf:KeyAccess>
         *          <tdf:EncryptionMethod></tdf:EncryptionMethod>
         *        </tdf:EncryptionInformation>
         *      </tdf:WrappedPDPKey>
         *    </tdf:KeyAccess>
         *  </tdf:EncryptionInformation>
         */

        auto encryptionInformationElement = xmlNewChild(rootNode,
                                                        ns,
                                                        reinterpret_cast<const xmlChar *>(kEncryptionInformationElement),
                                                        nullptr);


        auto keyAccessElement = xmlNewChild(encryptionInformationElement,
                                                        ns,
                                                        reinterpret_cast<const xmlChar *>(kKeyAccessElement),
                                                        nullptr);



        auto wrappedPDPKeyElement = xmlNewChild(keyAccessElement,
                                            ns,
                                            reinterpret_cast<const xmlChar *>(kWrappedPDPKeyElement),
                                            nullptr);

        // <tdf:EncryptedPolicyObject>2S2IaiClhsojZuLYYHiAw7hN...</tdf:EncryptedPolicyObject>
        {
            auto encryptedPolicyObject = ManifestDataModel::constructEncryptedPolicyObject(m_manifestDataModel);
            auto encodedSize = encoded_size(encryptedPolicyObject.size());
            std::string encodeBuffer(encodedSize, '0');
            auto actualEncodedBufSize = encode(encodeBuffer.data(), encryptedPolicyObject.data(), encryptedPolicyObject.size());
            encodeBuffer.resize(actualEncodedBufSize);

            xmlNewChild(wrappedPDPKeyElement,
                        ns,
                        reinterpret_cast<const xmlChar *>(kEncryptedPolicyObjectElement),
                        reinterpret_cast<const xmlChar *>(encodeBuffer.c_str()));
        }


        /*
         * <tdf:EncryptionMethod tdf:algorithm="AES">
         *   <tdf:KeySize>32</tdf:KeySize>
         *   <tdf:IVParams>MA==</tdf:IVParams>
         *   <tdf:AuthenticationTag>B20abww4lLmNOqa43sas</tdf:AuthenticationTag>
         * </tdf:EncryptionMethod>
         */
        {
            auto encryptionMethodElement = xmlNewChild(encryptionInformationElement,
                                                       ns,
                                                       reinterpret_cast<const xmlChar *>(kEncryptionMethodElement),
                                                       nullptr);

            std::string algorithm(kCipherAlgorithmGCM);
            xmlNewNsProp(encryptionMethodElement,
                         ns,
                         reinterpret_cast<const xmlChar *>(kAlgorithmAttribute),
                         reinterpret_cast<const xmlChar *>(algorithm.c_str()));

            auto keySizeStr = std::to_string(32);
            xmlNewChild(encryptionMethodElement,
                        ns,
                        reinterpret_cast<const xmlChar *>(kKeySizeElement),
                        reinterpret_cast<const xmlChar *>(keySizeStr.c_str()));

            auto iv = m_manifestDataModel.encryptionInformation.method.iv;
            xmlNewChild(encryptionMethodElement,
                        ns,
                        reinterpret_cast<const xmlChar *>(kIVParamsElement),
                        reinterpret_cast<const xmlChar *>(iv.c_str()));

            // TODO: THis need to come from the wrapped key if present, for remote key we can avoid it
//            std::string authenticationTag("B20abww4lLmNOqa43sas");
//            xmlNewChild(encryptionMethodElement,
//                        ns,
//                        reinterpret_cast<const xmlChar *>(kAuthenticationTagElement),
//                        reinterpret_cast<const xmlChar *>(authenticationTag.c_str()));
        }
    }

    /// Add 'Base64BinaryPayload' element.
    void TDFXMLWriter::addPayloadElement(xmlNodePtr rootNode, xmlNsPtr ns) {

        /* <Base64BinaryPayload> </Base64BinaryPayload> */
        auto payloadEncodedSize = encoded_size(m_binaryPayload.size());
        std::string encodeBuffer(payloadEncodedSize, '0');
        auto actualEncodedBufSize = encode(encodeBuffer.data(), m_binaryPayload.data(), m_binaryPayload.size());
        encodeBuffer.resize(actualEncodedBufSize);

        auto base64BinaryPayloadElement = xmlNewChild(rootNode,
                                            ns,
                                            reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement),
                                            reinterpret_cast<const xmlChar *>(encodeBuffer.c_str()));

        // Add 'isEncrypted' attribute to element tdf:Base64BinaryPayload
        std::string isEncryptedStr = m_manifestDataModel.payload.isEncrypted ? "true" : "false";
        xmlNewNsProp(base64BinaryPayloadElement,
                    ns,
                    reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute),
                    reinterpret_cast<const xmlChar *>(isEncryptedStr.c_str()));

        xmlNewNsProp(base64BinaryPayloadElement,
                        ns,
                    reinterpret_cast<const xmlChar *>(kMediaTypeAttribute),
                    reinterpret_cast<const xmlChar *>(m_manifestDataModel.payload.mimeType.c_str()));
    }



    /// Finalize archive entry.
    void TDFXMLWriter::finish() {

        XmlDocFreePtr doc{ xmlNewDoc(reinterpret_cast<const xmlChar *>(kICTDFVersion))};
        if (!doc) {
            std::string errorMsg{"Fail to create XML document for creating the TDF"};
            ThrowException(std::move(errorMsg));
        }

        xmlNode* rootNode = xmlNewNode(nullptr, reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement));
        if (!rootNode) {
            std::string errorMsg{"Fail to create 'TrustedDataObject' node"};
            ThrowException(std::move(errorMsg));
        }

        // Create a name spaces
        xmlNsPtr ns = xmlNewNs(rootNode,
                               reinterpret_cast<const xmlChar *>(kTDFNameSpaceHref),
                               nullptr);

        xmlNsPtr xsiNs = xmlNewNs(rootNode,
                                  reinterpret_cast<const xmlChar *>(kXMLHref),
                                  reinterpret_cast<const xmlChar *>(kXSIPrefix));

        xmlNsPtr tdfNs = xmlNewNs(rootNode,
                                  reinterpret_cast<const xmlChar *>(kTDFNameSpaceHref),
                                  reinterpret_cast<const xmlChar *>(kTDFPrefix));
        if (!ns || !xsiNs || !tdfNs) {
            std::string errorMsg{"Fail to create namespace for creating XML TDF"};
            ThrowException(std::move(errorMsg));
        }

        xmlSetNs(rootNode, tdfNs);
        xmlDocSetRootElement(doc.get(), rootNode);

        // Add 'tdf:HandlingAssertion' elements
        addHandlingAssertionElement(rootNode, tdfNs);

        // Add 'tdf:Assertion' elements
        addDefaultAssertionElement(rootNode, tdfNs);

        // Add 'tdf:EncryptionInformationElement' element
        addEncryptionInformationElement(rootNode, tdfNs);

        // Add 'tdf:Base64BinaryPayload' element
        addPayloadElement(rootNode, tdfNs);

        // Load the xml doc into buffer
        xmlChar* output = nullptr;
        XMLCharFreePtr xmlCharFreePtr{output};
        int size = 0;

        xmlDocDumpMemoryEnc(doc.get(), &output, &size, kXMLEncoding);

        bool valid = m_XmlValidatorPtr.validate(doc.get());
        if (!valid) {
            std::string errorMsg{"Error - document did not pass schema validation"};
            ThrowException(std::move(errorMsg));
        }

        auto bytes = gsl::make_span(reinterpret_cast<const gsl::byte *>(output), size);
        m_outputProvider.writeBytes(bytes);
    }

    /// Establish a validator schema to verify input against
    bool TDFXMLWriter::setValidatorSchema(const std::string& url) {
        m_XmlValidatorPtr.setSchema(url);
        return m_XmlValidatorPtr.isSchemaValid();
    }

    /// Add 'tdf:HandlingAssertion' element.
    void TDFXMLWriter::addHandlingAssertionElement(xmlNodePtr rootNode, xmlNsPtr ns) {
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
        for (const auto& handlingAssertion: m_manifestDataModel.handlingAssertions) {

            auto handlingAssertionElement = xmlNewChild(rootNode, ns,
                                                        reinterpret_cast<const xmlChar *>(kHandlingAssertionElement),
                                                        nullptr);

            if (handlingAssertion.getScope() == Scope::Unknown) {
                std::string errorMsg{"Unknow scope attribute for HandlingAssertion"};
                ThrowException(std::move(errorMsg));
            }

            auto scopeAsStrView = magic_enum::enum_name(handlingAssertion.getScope());
            std::string scopeAsStr{scopeAsStrView};
            xmlNewNsProp(handlingAssertionElement,
                         ns,
                         reinterpret_cast<const xmlChar *>(kScopeAttribute),
                         reinterpret_cast<const xmlChar *>(scopeAsStr.c_str()));

            if (handlingAssertion.getAppliesToState() == AppliesToState::Unknown) {
                std::string errorMsg{"Unknow appliesToState for HandlingAssertion"};
                ThrowException(std::move(errorMsg));
            }

            auto appliesToStateAsStrView = magic_enum::enum_name(handlingAssertion.getAppliesToState());
            std::string appliesToStateAsStr{appliesToStateAsStrView};
            xmlNewNsProp(handlingAssertionElement,
                         ns,
                         reinterpret_cast<const xmlChar *>(kAppliesToStateAttribute),
                         reinterpret_cast<const xmlChar *>(appliesToStateAsStr.c_str()));

            if (!handlingAssertion.getId().empty()) {
                xmlNewNsProp(handlingAssertionElement,
                             ns,
                             reinterpret_cast<const xmlChar *>(kIdAttribute),
                             reinterpret_cast<const xmlChar *>(handlingAssertion.getId().c_str()));
            }

            auto handlingStatementElement = xmlNewChild(handlingAssertionElement, ns,
                                                        reinterpret_cast<const xmlChar *>(kHandlingStatementElement),
                                                        nullptr);

            xmlNodePtr edhNode = nullptr;
            auto handlingStatement = handlingAssertion.getHandlingStatement();
            xmlParseInNodeContext(handlingStatementElement,
                                  handlingStatement.c_str(),
                                  handlingStatement.size(),
                                  0,
                                  &edhNode);
            if (edhNode) {
                xmlAddChild(handlingStatementElement, edhNode);
            }
        }
    }


    /// Add 'tdf:Assertion' element.
    void TDFXMLWriter::addDefaultAssertionElement(xmlNodePtr rootNode, xmlNsPtr ns) {
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
        for (const auto& defaultAssertion: m_manifestDataModel.defaultAssertions) {

            auto assertionElement = xmlNewChild(rootNode,
                                                ns,
                                                reinterpret_cast<const xmlChar *>(kAssertionElement),
                                                nullptr);

            if (defaultAssertion.getScope() == Scope::Unknown) {
                std::string errorMsg{"Unknow scope attribute for HandlingAssertion"};
                ThrowException(std::move(errorMsg));
            }

            auto scopeAsStrView = magic_enum::enum_name(defaultAssertion.getScope());
            std::string scopeAsStr{scopeAsStrView};
            xmlNewNsProp(assertionElement,
                         ns,
                         reinterpret_cast<const xmlChar *>(kScopeAttribute),
                         reinterpret_cast<const xmlChar *>(scopeAsStr.c_str()));


            if (!defaultAssertion.getId().empty()) {
                xmlNewNsProp(assertionElement,
                             ns,
                             reinterpret_cast<const xmlChar *>(kIdAttribute),
                             reinterpret_cast<const xmlChar *>(defaultAssertion.getId().c_str()));
            }

            if (!defaultAssertion.getType().empty()) {
                xmlNewNsProp(assertionElement,
                             ns,
                             reinterpret_cast<const xmlChar *>(kTypeAttribute),
                             reinterpret_cast<const xmlChar *>(defaultAssertion.getType().c_str()));
            }

            auto statementGroup = defaultAssertion.getStatementGroup();
            auto statementGroupType = statementGroup.getStatementType();
            if (statementGroupType == StatementType::Unknow) {
                std::string errorMsg{"Unknow statement type for assertion"};
                ThrowException(std::move(errorMsg));
            }

            auto statementTypeAsStrView = magic_enum::enum_name(statementGroupType);
            std::string statementTypeStr{statementTypeAsStrView};

            auto statementGroupElement = xmlNewChild(assertionElement, ns,
                                                     reinterpret_cast<const xmlChar *>(statementTypeStr.c_str()),
                                                     reinterpret_cast<const xmlChar *>(statementGroup.getValue().c_str()));


            std::string isEncryptedStr = statementGroup.getIsEncrypted() ? "true" : "false";
            xmlNewNsProp(statementGroupElement,
                         ns,
                         reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute),
                         reinterpret_cast<const xmlChar *>(isEncryptedStr.c_str()));


            if (!statementGroup.getFilename().empty()) {
                xmlNewNsProp(statementGroupElement,
                             ns,
                             reinterpret_cast<const xmlChar *>(kFilenameAttribute),
                             reinterpret_cast<const xmlChar *>(statementGroup.getFilename().c_str()));
            }

            if (!statementGroup.getMediaType().empty()) {
                xmlNewNsProp(statementGroupElement,
                             ns,
                             reinterpret_cast<const xmlChar *>(kMediaTypeAttribute),
                             reinterpret_cast<const xmlChar *>(statementGroup.getMediaType().c_str()));
            }

            if (!statementGroup.getUri().empty()) {
                xmlNewNsProp(statementGroupElement,
                             ns,
                             reinterpret_cast<const xmlChar *>(kUriAttribute),
                             reinterpret_cast<const xmlChar *>(statementGroup.getUri().c_str()));
            }
        }

    }

    /// Create XML element and xmlTextWriter
    void TDFXMLWriter::createElement(xmlTextWriterPtr writer, const std::string& elementName,
                                     const std::string& elementValue,
                                     XMLAttributesNamesAndValues xmlAttributesNamesAndValues) {

        auto rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(elementName.c_str()));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement - "};
            errorMsg.append(elementName);
            ThrowException(std::move(errorMsg));
        }

        for (const auto &attribute : xmlAttributesNamesAndValues) {
            rc = xmlTextWriterWriteAttribute(writer, reinterpret_cast<const xmlChar *>(attribute.first.c_str()),
                                             reinterpret_cast<const xmlChar *>(attribute.second.c_str()));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteAttribute - "};
                errorMsg.append(elementName);
                ThrowException(std::move(errorMsg));
            }
        }

        if (!elementValue.empty()) {
            rc = xmlTextWriterWriteRawLen(writer,
                                          reinterpret_cast<const xmlChar *>(elementValue.data()),
                                          elementValue.size());
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteRawLen - "};
                errorMsg.append(elementName);
                ThrowException(std::move(errorMsg));
            }
        }

        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement - "};
            errorMsg.append(elementName);
            ThrowException(std::move(errorMsg));
        }
    }
}
