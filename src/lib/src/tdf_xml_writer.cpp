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

    /// Destructor
    TDFXMLWriter::~TDFXMLWriter() {
        if (m_schemaValidatorPtr) {
            delete m_schemaValidatorPtr;
            m_schemaValidatorPtr = 0;
        }
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

        // Add 'tdf:EncryptionInformationElement' element
        addEncryptionInformationElement(rootNode, tdfNs);

        // Add 'tdf:Base64BinaryPayload' element
        addPayloadElement(rootNode, tdfNs);

        // Load the xml doc into buffer
        xmlChar* output = nullptr;
        XMLCharFreePtr xmlCharFreePtr{output};
        int size = 0;

        xmlDocDumpMemoryEnc(doc.get(), &output, &size, kXMLEncoding);

        if (m_schemaValidatorPtr) {
            bool valid = m_schemaValidatorPtr->validateXML(doc.get());
            if (!valid) {
                std::string errorMsg{"Error - document did not pass schema validation"};
                ThrowException(std::move(errorMsg));
            }
        }

        auto bytes = gsl::make_span(reinterpret_cast<const gsl::byte *>(output), size);
        m_outputProvider.writeBytes(bytes);
    }

    /// Establish a validator schema to verify input against
    bool TDFXMLWriter::setValidatorSchema(const char *url) {
        m_schemaValidatorPtr = new TDFXMLValidator(url);
        return m_schemaValidatorPtr->isSchemaValid();
    }

    /// Add 'tdf:HandlingAssertion' element.
    void TDFXMLWriter::addHandlingAssertionElement(xmlTextWriterPtr writer) {
        /*
         * <tdf:HandlingAssertion tdf:id="policybinding" tdf:scope="PAYL" tdf:appliesToState="encrypted">
         *    <tdf:Binding>
         *      <tdf:Signer tdf:issuer="https://kas1.example.com:4000"/>
         *      <tdf:SignatureValue tdf:signatureAlgorithm="HS256">RXhwZWN0ZWQgU3RyaW5nIFZhbHVl</tdf:SignatureValue>
		 *    </tdf:Binding>
         * </tdf:HandlingAssertion>
         */
        auto rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kHandlingAssertionElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:HandlingAssertion)"};
            ThrowException(std::move(errorMsg));
        }

        XMLAttributesNamesAndValues xmlAttributesNamesAndValues = {{ kIdElement, "policybinding"},
                                                                   { kScopeElement, "PAYL"},
                                                                   {kAppliesToStateElement, "encrypted"}};
        for (const auto &attribute : xmlAttributesNamesAndValues) {
            rc = xmlTextWriterWriteAttribute(writer, reinterpret_cast<const xmlChar *>(attribute.first.c_str()),
                                             reinterpret_cast<const xmlChar *>(attribute.second.c_str()));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteAttribute - "};
                errorMsg.append(kHandlingAssertionElement);
                ThrowException(std::move(errorMsg));
            }
        }

        rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kBindingElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement - tdf:Binding"};
            ThrowException(std::move(errorMsg));
        }

        // tdf:Signer element
        createElement(writer, kSignerElement, {},
                      {{ kIssuerElement, m_manifestDataModel.encryptionInformation.keyAccessObjects[0].url}});

        // tdf:SignatureValue element
        createElement(writer, kSignatureValueElement, m_manifestDataModel.encryptionInformation.keyAccessObjects[0].policyBinding,
                      {{ kSignatureAlgorithmElement, "HS256"}});


        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement - - tdf:Binding"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement - tdf:HandlingAssertion"};
            ThrowException(std::move(errorMsg));
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
