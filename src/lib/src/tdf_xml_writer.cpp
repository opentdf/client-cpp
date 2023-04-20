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
    TDFXMLWriter::TDFXMLWriter(IOutputProvider& outputProvider, std::string manifestFilename, std::string payloadFileName)
            : m_manifestFilename{std::move(manifestFilename)}, m_payloadFileName{std::move(payloadFileName)},
            m_outputProvider(outputProvider){
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

    /// Create XML TDF buffer
    xmlBufferPtr TDFXMLWriter::createTDFXML() {

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
            std::string errorMsg{"Error creating the xml writer and starting document"};
            ThrowException(std::move(errorMsg));
        }

        // Start an element named "TrustedDataCollection". Since this is the first
        // element, this will be the root element of the XML TDF
        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kTrustedDataCollectionElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement (TrustedDataCollection)"};
            ThrowException(std::move(errorMsg));
        }

        // Start an element named "TrustedDataObject".
        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kTrustedDataObjectElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement (TrustedDataObject)"};
            ThrowException(std::move(errorMsg));
        }

        // Add 'ReferenceValuePayload'
        addReferenceValuePayloadElement(writer.get());

        // Add 'EncryptionInformation'
        addEncryptionInformationElement(writer.get());

        // Add assertions
        //addHandlingAssertionElement(writer.get());

        // Add 'Base64BinaryPayload'
        addPayloadElement(writer.get());

        // Close the element named TrustedDataObject
        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement (TrustedDataObject)"};
            ThrowException(std::move(errorMsg));
        }

        // Close the element named TrustedDataCollection
        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement (TrustedDataCollection)"};
            ThrowException(std::move(errorMsg));
        }

        // Close the document
        rc = xmlTextWriterEndDocument(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndDocument"};
            ThrowException(std::move(errorMsg));
        }

        return xmlBuffer.release();
    }

    /// Finalize archive entry.
    void TDFXMLWriter::finish() {
        auto xmlBufferPtr = createTDFXML();

        xmlBufferFreePtr xmlBuffer{xmlBufferPtr};
        if (!xmlBuffer) {
            std::string errorMsg{"Fail to create XML Buffer for creating the XML TDF"};
            ThrowException(std::move(errorMsg));
        }

        auto data = gsl::make_span(reinterpret_cast<const gsl::byte *>(xmlBuffer.get()->content),
                                   xmlBufferLength(xmlBuffer.get()));
        m_outputProvider.writeBytes(data);
    }

    /// Add 'tdf:ReferenceValuePayload' element.
    void TDFXMLWriter::addReferenceValuePayloadElement(xmlTextWriterPtr writer) {

        /* <tdf:ReferenceValuePayload tdf:isEncrypted="true" tdf:uri="zip://0.payload"/> */
        // Start an element named "tdf:ReferenceValuePayload" child of "TrustedDataObject"
        auto rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kTDFReferenceValuePayload));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement - tdf:ReferenceValuePayload"};
            ThrowException(std::move(errorMsg));
        }

        // Add 'isEncrypted' attribute to element tdf:ReferenceValuePayload
        std::string isEncryptedStr = m_manifestDataModel.payload.isEncrypted ? "true" : "false";
        rc = xmlTextWriterWriteAttribute(writer, reinterpret_cast<const xmlChar *>(kIsEncryptedAttribute),
                                         reinterpret_cast<const xmlChar *>(isEncryptedStr.c_str()));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteAttribute (isEncrypted)"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterWriteAttribute(writer, reinterpret_cast<const xmlChar *>(kMediaTypeAttribute),
                                         reinterpret_cast<const xmlChar *>(m_manifestDataModel.payload.mimeType.c_str()));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteAttribute (mediaType)"};
            ThrowException(std::move(errorMsg));
        }

        // Close the element named tdf:ReferenceValuePayload
        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:ReferenceValuePayload)"};
            ThrowException(std::move(errorMsg));
        }
    }

    /// Add 'tdf:EncryptionInformation' element.
    void TDFXMLWriter::addEncryptionInformationElement(xmlTextWriterPtr writer) {

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
        auto rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kEncryptionInformationElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:EncryptionInformation)"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kKeyAccessElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:KeyAccess)"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kWrappedPDPKeyElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:WrappedPDPKey)"};
            ThrowException(std::move(errorMsg));
        }

        // <tdf:KeyValue>YBkqvsiDnyDfw5JQzux2S2IaiClhsojZuLYYHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==</tdf:KeyValue>
        {
            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kKeyValueElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:KeyValue)"};
                ThrowException(std::move(errorMsg));
            }

            if (m_manifestDataModel.encryptionInformation.keyAccessObjects.size() != 1) {
                std::string errorMsg{"Invalid count of key access objects."};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterWriteRawLen(writer,
                                          reinterpret_cast<const xmlChar *>(m_manifestDataModel.encryptionInformation.keyAccessObjects[0].wrappedKey.data()),
                                          m_manifestDataModel.encryptionInformation.keyAccessObjects[0].wrappedKey.size());
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteRawLen - tdf:WrappedPDPKey"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:KeyValue)"};
                ThrowException(std::move(errorMsg));
            }
        }

        // <tdf:EncryptedPolicyObject>2S2IaiClhsojZuLYYHiAw7hN...</tdf:EncryptedPolicyObject>
        {
            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kEncryptedPolicyObjectElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:EncryptedPolicyObject)"};
                ThrowException(std::move(errorMsg));
            }

            auto policy = createEncryptedPolicyObject();
            rc = xmlTextWriterWriteRawLen(writer,
                                          reinterpret_cast<const xmlChar *>(policy.data()),
                                          policy.size());
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteRawLen:tdf:EncryptedPolicyObject"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:EncryptedPolicyObject)"};
                ThrowException(std::move(errorMsg));
            }
        }

        rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kEncryptionInformationElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:EncryptionInformation)"};
            ThrowException(std::move(errorMsg));
        }


        /*
         *   <tdf:KeyAccess>
         *     <tdf:RemoteStoredKey tdf:protocol="KAS" tdf:uri="http://kas.example.com:4000">
         *     </tdf:RemoteStoredKey>
         *   </tdf:KeyAccess>
         */
        {
            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kKeyAccessElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:KeyAccess)"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kRemoteStoredKeyElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:RemoteStoredKey)"};
                ThrowException(std::move(errorMsg));
            }

            auto protocol = m_manifestDataModel.encryptionInformation.keyAccessObjects[0].protocol;
            rc = xmlTextWriterWriteAttribute(writer, reinterpret_cast<const xmlChar *>(kProtocolElement),
                                             reinterpret_cast<const xmlChar *>(protocol.c_str()));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteAttribute (tdf:protocol)"};
                ThrowException(std::move(errorMsg));
            }

            auto uri = m_manifestDataModel.encryptionInformation.keyAccessObjects[0].url;
            rc = xmlTextWriterWriteAttribute(writer, reinterpret_cast<const xmlChar *>(kUriElement),
                                             reinterpret_cast<const xmlChar *>(uri.c_str()));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteAttribute (tdf:uri)"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:RemoteStoredKey)"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:KeyAccess)"};
                ThrowException(std::move(errorMsg));
            }
        }

        /*
         * <tdf:EncryptionMethod tdf:algorithm="AES">
         *   <tdf:KeySize>32</tdf:KeySize>
         *   <tdf:IVParams>MA==</tdf:IVParams>
         *   <tdf:AuthenticationTag>B20abww4lLmNOqa43sas</tdf:AuthenticationTag>
         * </tdf:EncryptionMethod>
         */
        {
            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kEncryptionMethodElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:EncryptionMethod)"};
                ThrowException(std::move(errorMsg));
            }

            std::string algorithm("AES");
            rc = xmlTextWriterWriteAttribute(writer, reinterpret_cast<const xmlChar *>(kAlgorithmElement),
                                             reinterpret_cast<const xmlChar *>(algorithm.c_str()));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteAttribute (tdf:algorithm)"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kKeySizeElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:KeySize)"};
                ThrowException(std::move(errorMsg));
            }

            auto keySizeStr = std::to_string(32);
            rc = xmlTextWriterWriteRawLen(writer,
                                          reinterpret_cast<const xmlChar *>(keySizeStr.data()),
                                          keySizeStr.size());
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteRawLen:tdf:KeySize"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:KeySize)"};
                ThrowException(std::move(errorMsg));
            }


            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kIVParamsElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:IVParams)"};
                ThrowException(std::move(errorMsg));
            }

            // TODO: THis need to come from the wrapped key if present, for remote key we can avoid it
            auto iv = m_manifestDataModel.encryptionInformation.method.iv;
            rc = xmlTextWriterWriteRawLen(writer,
                                          reinterpret_cast<const xmlChar *>(iv.data()),
                                          iv.size());
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteRawLen:tdf:IVParams"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:IVParams)"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kAuthenticationTagElement));
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterStartElement (tdf:AuthenticationTag)"};
                ThrowException(std::move(errorMsg));
            }

            // TODO: THis need to come from the wrapped key if present, for remote key we can avoid it
            std::string authenticationTag("B20abww4lLmNOqa43sas");
            rc = xmlTextWriterWriteRawLen(writer,
                                          reinterpret_cast<const xmlChar *>(authenticationTag.data()),
                                          authenticationTag.size());
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterWriteRawLen:tdf:AuthenticationTag"};
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:AuthenticationTag)"};
                ThrowException(std::move(errorMsg));
            }

            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:EncryptionMethod)"};
                ThrowException(std::move(errorMsg));
            }
        }

        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement (ttdf:EncryptionInformation)"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:WrappedPDPKey)"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:KeyAccess))"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement (tdf:EncryptionInformation))"};
            ThrowException(std::move(errorMsg));
        }
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

    /// Add 'Base64BinaryPayload' element.
    void TDFXMLWriter::addPayloadElement(xmlTextWriterPtr writer) {

        /* <Base64BinaryPayload> </Base64BinaryPayload> */
        auto rc = xmlTextWriterStartElement(writer, reinterpret_cast<const xmlChar *>(kBase64BinaryPayloadElement));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement - Base64BinaryPayload"};
            ThrowException(std::move(errorMsg));
        }

        auto payloadEncodedSize = encoded_size(m_binaryPayload.size());
        std::vector<char> encodeBuffer(payloadEncodedSize);
        auto actualEncodedBufSize = encode(encodeBuffer.data(), m_binaryPayload.data(), m_binaryPayload.size());

        rc = xmlTextWriterWriteRawLen(writer,
                                      reinterpret_cast<const xmlChar *>(encodeBuffer.data()),
                                      actualEncodedBufSize);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterWriteRawLen - Base64BinaryPayload"};
            ThrowException(std::move(errorMsg));
        }

        // Close the element named tdf:ReferenceValuePayload
        rc = xmlTextWriterEndElement(writer);
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement - Base64BinaryPayload"};
            ThrowException(std::move(errorMsg));
        }
    }

    /// Create encrypted policy object.
    std::string TDFXMLWriter::createEncryptedPolicyObject() {
        /*
         *   <EncryptedPolicyObject>
         *     <policy>base64 of policy</policy>
         *     <policySignature>payloadKey.sign(policyb64)</policySignature>
         *     <encryptedMetadata>payloadKey(json object)</encryptedMetadata>
         *   </EncryptedPolicyObject>
         */
        xmlBufferFreePtr xmlBuffer{xmlBufferCreate()};
        if (!xmlBuffer) {
            std::string errorMsg{"Fail to create XML Buffer for creating the EncryptedPolicyObject XML"};
            ThrowException(std::move(errorMsg));
        }

        // Create a new XmlWriter to write the xml with no compression.
        xmlTextWriterFreePtr writer{xmlNewTextWriterMemory(xmlBuffer.get(), 0)};
        if (!writer) {
            std::string errorMsg{"Error creating the xml writer"};
            ThrowException(std::move(errorMsg));
        }

        auto rc = xmlTextWriterStartDocument(writer.get(), nullptr, nullptr, nullptr);
        if (rc < 0) {
            std::string errorMsg{"Error creating the xml writer and starting document"};
            ThrowException(std::move(errorMsg));
        }

        rc = xmlTextWriterStartElement(writer.get(), reinterpret_cast<const xmlChar *>(kEncryptedPolicyObject));
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterStartElement - EncryptedPolicyObject"};
            ThrowException(std::move(errorMsg));
        }

        if (m_manifestDataModel.encryptionInformation.keyAccessObjects.size() != 1) {
            std::string errorMsg{"Invalid count of key access objects."};
            ThrowException(std::move(errorMsg));
        }

        // Add 'policy'
        createElement(writer.get(), kPolicy, m_manifestDataModel.encryptionInformation.policy, {});

        // Add 'policyBinding'
        auto policyBinding = m_manifestDataModel.encryptionInformation.keyAccessObjects[0].policyBinding;
        createElement(writer.get(), kPolicyBinding, policyBinding, {});

        // Add 'encryptedMetaData'
        auto encryptedMetaData = m_manifestDataModel.encryptionInformation.keyAccessObjects[0].encryptedMetadata;
        createElement(writer.get(), kEncryptedMetadata, policyBinding, {});

        rc = xmlTextWriterEndElement(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndElement - EncryptedPolicyObject"};
            ThrowException(std::move(errorMsg));
        }

        // Close the document
        rc = xmlTextWriterEndDocument(writer.get());
        if (rc < 0) {
            std::string errorMsg{"Error at xmlTextWriterEndDocument"};
            ThrowException(std::move(errorMsg));
        }

        std::string data(reinterpret_cast<const char *>(xmlBuffer.get()->content),
                         xmlBufferLength(xmlBuffer.get()));

        auto encodedSize = encoded_size(data.size());
        std::string base64Data (encodedSize, '\0');
        auto actualEncodedBufSize = encode(base64Data.data(), data.data(), data.size());
        base64Data.resize(actualEncodedBufSize);

        return base64Data;
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
