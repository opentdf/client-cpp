/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/08/13
//
#include <cinttypes>

#include "utils.h"
#include "entity_object.h"
#include "attribute_object.h"
#include "sdk_constants.h"
#include "crypto/ec_key_pair.h"
#include "network_interface.h"
#include "oidc_service.h"
#include "nanotdf.h"
#include "nanotdf_builder.h"
#include "nanotdf_builder_impl.h"
#include "nanotdf_client.h"
#include "nanotdf_impl.h"
#include "file_io_provider.h"
#include "benchmark.h"

#include <jwt-cpp/jwt.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include "nlohmann/json.hpp"

namespace virtru {

    static const auto UserAgentValuePostFix = Utils::getUserAgentValuePostFix();
    static const auto clientValue = Utils::getClientValue();

    /// Constructs a nano TDF client instance.
    /// NOTE: should me used for only offline decrypt operation.
    NanoTDFClient::NanoTDFClient() : NanoTDFClient("http://eas", "NO_OWNER", "", "", "") {
        m_nanoTdfBuilder->setOffline(true);
    }

    /// Constructor
    NanoTDFClient::NanoTDFClient(const std::string& easUrl, const std::string& user)
            : NanoTDFClient(easUrl, user, "", "", "") {

    }

    /// Constructor
    NanoTDFClient::NanoTDFClient(const std::string& easUrl, const std::string& user,
            const std::string& clientKeyFileName, const std::string& clientCertFileName,
            const std::string& sdkConsumerCertAuthority)
            : TDFClientBase(easUrl, user, clientKeyFileName, clientCertFileName, sdkConsumerCertAuthority) {

        m_nanoTdfBuilder = std::make_unique<NanoTDFBuilder>(m_user);
        m_nanoTdfBuilder->setEasUrl(m_easUrl);
    }

    /// Constructor
    NanoTDFClient::NanoTDFClient(const OIDCCredentials& oidcCredentials, const std::string &kasUrl)
            :TDFClientBase(kasUrl, "", "", "", "") {
        m_nanoTdfBuilder = std::make_unique<NanoTDFBuilder>(oidcCredentials.getClientId());
        m_nanoTdfBuilder->setKasUrl(kasUrl);
        m_nanoTdfBuilder->enableOIDC(true);

        m_oidcCredentials = std::make_unique<OIDCCredentials>(oidcCredentials);
    }

    /// Destructor
    NanoTDFClient::~NanoTDFClient() = default;

    /// Encrypt the data by reading from inputProvider and writing to outputProvider.
    void NanoTDFClient::encryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) {
        LogError("Not implemented");
    }

    /// Decrypt the tdf data by reading from inputProvider and writing to outputProvider.
    void NanoTDFClient::decryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) {
        LogError("Not implemented");
    }

    /// Encrypt the file to tdf format.
    void NanoTDFClient::encryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) {

        Benchmark benchmark("Total encrypt file time");

        // Initialize the nano tdf builder
        initNanoTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto nanoTDF = m_nanoTdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {
            nanoTDF->encryptFile(tdfStorageType.m_filePath, outFilepath);
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
    }

    /// Decrypt file that are encrypted using old version of SDKs.
    void NanoTDFClient::decryptFileUsingOldFormat(const std::string& inFilepath, const std::string& outFilepath) {
        // Initialize the nano tdf builder
        initNanoTDFBuilder(false);

        m_nanoTdfBuilder->enableFlagToUseOldFormatNTDF();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto nanoTDF = m_nanoTdfBuilder->setPolicyObject(policyObject).build();
        nanoTDF->decryptFile(inFilepath, outFilepath);
    }

    /// Decrypt file to nano tdf file format.
    void NanoTDFClient::decryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) {

        Benchmark benchmark("Total decrypt file time");

        // Initialize the nano tdf builder
        initNanoTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto nanoTDF = m_nanoTdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {
            nanoTDF->decryptFile(tdfStorageType.m_filePath, outFilepath);
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
    }

    /// Decrypt the bytes to nano tdf format.
    std::vector<VBYTE> NanoTDFClient::decryptData(const TDFStorageType &tdfStorageType) {

        Benchmark benchmark("Total decrypt data time");

        // Initialize the nano tdf builder
        initNanoTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto nanoTDF = m_nanoTdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {
            std::string_view dataView(reinterpret_cast<const char*>(tdfStorageType.m_tdfBuffer.data()),
                                      tdfStorageType.m_tdfBuffer.size());
            auto bufferView = nanoTDF->decryptData(dataView);
            std::vector<VBYTE> decryptedData(bufferView.begin(), bufferView.end());
            return decryptedData;
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
        return {};
    }

    /// Encrypt the bytes to tdf format.
    std::vector<VBYTE> NanoTDFClient::encryptData(const TDFStorageType &tdfStorageType) {

        Benchmark benchmark("Total encrypt data time");

        // Initialize the nano tdf builder
        initNanoTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto nanoTDF = m_nanoTdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {
            std::string_view dataView(reinterpret_cast<const char*>(tdfStorageType.m_tdfBuffer.data()),
                                      tdfStorageType.m_tdfBuffer.size());
            auto bufferView = nanoTDF->encryptData(dataView);
            std::vector<VBYTE> encryptedData(bufferView.begin(), bufferView.end());
            return encryptedData;
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
        return {};
    }

    /// Decrypt part of the data from tdf storage type.
    /// \param tdfStorageType - The type of the nano tdf.
    /// \param offset - The offset within the plaintext to return
    /// \param length - The length of the plaintext to return
    /// \return std::vector - The vector containing the decrypted data.
    /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
    /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
    /// return value.
    std::vector<VBYTE> NanoTDFClient::decryptDataPartial(const TDFStorageType &tdfStorageType, size_t offset, size_t length) {

        // Initialize the micro tdf builder
        initNanoTDFBuilder(false);

        m_nanoTdfBuilder->disableFlagToUseOldFormatNTDF();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto nanoTDF = m_nanoTdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {
            std::ifstream inStream( tdfStorageType.m_filePath, std::ios::binary | std::ios::ate);
            if (!inStream) {
                std::string errorMsg{"Failed to open file for reading - "};
                errorMsg.append(tdfStorageType.m_filePath);
                ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            }

            std::ostringstream stringStream;
            stringStream << inStream.rdbuf();

            std::string plainData(nanoTDF->decryptString(stringStream.str()));
            auto subStr = plainData.substr(offset, length);
            std::vector<VBYTE> buffer(subStr.begin(), subStr.end());
            return buffer;

        }  else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {
            std::string plainData(nanoTDF->decryptString(tdfStorageType.m_tdfBuffer));
            auto subStr = plainData.substr(offset, length);

            std::vector<VBYTE> buffer(subStr.begin(), subStr.end());
            return buffer;
        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::S3) {
            std::string errorMsg{"S3 not implemented"};
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            // TODO FIXME - needs implementation
            std::vector<VBYTE> buffer(0, 1);
            return buffer;
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        return {};
    }

    /// Decrypt data from nano tdf format that are encrypted using old version of SDKs.
    std::string NanoTDFClient::decryptStringUsingOldFormat(const std::string &encryptedData) {

        // Initialize the micro tdf builder
        initNanoTDFBuilder(false);

        m_nanoTdfBuilder->enableFlagToUseOldFormatNTDF();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto nanoTDF = m_nanoTdfBuilder->setPolicyObject(policyObject).build();
        std::string plainData(nanoTDF->decryptString(encryptedData));
        return plainData;
    }

    ///Add data attribute
    void NanoTDFClient::addDataAttribute(const std::string &dataAttribute, const std::string &kasURL) {
        LogTrace("NanoTDFClient::addDataAttribute");

        std::string userKasURL{kasURL};
        if (userKasURL.empty()) {
            userKasURL = m_nanoTdfBuilder->m_impl->m_kasUrl;
        }

        if (userKasURL != m_nanoTdfBuilder->m_impl->m_kasUrl){
            LogWarn("Multi KAS is not supported");
        }

        std::string displayName;
        m_dataAttributeObjects.emplace_back(dataAttribute, displayName,
                                            m_nanoTdfBuilder->m_impl->m_kasPublicKey, userKasURL);
    }

    /// Get vector of entity attribute objects
    std::vector<AttributeObject> NanoTDFClient::getEntityAttrObjects() {
        std::vector<AttributeObject> entityAttributesObjects;

        initNanoTDFBuilder(false);
        std::vector<std::string> attributesAsJwt = m_nanoTdfBuilder->m_impl->m_entityObject.getAttributesAsJWT();

        //for each attributeObj JWT in the JWT vector
        for (auto& attributeObj : attributesAsJwt) {
            //decode JWT
            auto jwtToken = jwt::decode(attributeObj);
            //get AttributeObject from JWT payload
            AttributeObject attributeObject{jwtToken.get_payload()};
            //get unique resource locator from AttributeObject and add to vector
            entityAttributesObjects.push_back(attributeObject);
        }
        return entityAttributesObjects;
    }

    /// Get vector of subject attribute objects
    /// \return Return vector of subject attribute objects
    std::vector<AttributeObject> NanoTDFClient::getSubjectAttrObjects() {

        std::vector<AttributeObject> subjectAttributesObjects;
        initNanoTDFBuilder(false);
        auto attributes = m_oidcService->getClaimsObjectAttributes();

        //for each attributeObj JWT in the JWT vector
        std::string emptyDisplayName;
        subjectAttributesObjects.reserve(attributes.size());
        for (auto& attribute : attributes) {
            AttributeObject attributeObject{attribute, emptyDisplayName,
                                            m_nanoTdfBuilder->m_impl->m_kasPublicKey,
                                            m_nanoTdfBuilder->m_impl->m_kasUrl,
                                            false};

            subjectAttributesObjects.push_back(attributeObject);
        }
        return subjectAttributesObjects;
    }

    /// Set the entity private key(In PEM format), which will be used by this SDK for encryption/decryption of
    /// the payload/policy. The private key should be from one of predefined curves defined in tdf_constants.h
    void NanoTDFClient::setEntityPrivateKey(const std::string& privateKey, EllipticCurve curve) {
        m_nanoTdfBuilder->setEntityPrivateKey(privateKey, curve);
    }


    /// Set the signer private key(In PEM format). Calling this method enables the signature entry in nano tdf
    /// The ECC private key should be from one of predefined curves which are defined in tdf_constants.h
    void NanoTDFClient::setSignerPrivateKey(const std::string& signerPrivateKey, EllipticCurve curve) {
        m_nanoTdfBuilder->setSignerPrivateKey(signerPrivateKey, curve);
    }

    /// Set the kas public key(In PEM format). This can be used for offline mode.
    void NanoTDFClient::setDecrypterPublicKey(const std::string& decrypterPublicKey) {
        m_nanoTdfBuilder->setKasPublicKey(decrypterPublicKey);
    }

    /// Validate the TDF on decrypt(check if the TDF is singed by right entity). Throws exception
    /// on decrypt if the given public key doesn't match the one in TDF.
    void NanoTDFClient::validateSignature(const std::string& signerPublicKey) {
        m_nanoTdfBuilder->validateSignature(signerPublicKey);
    }

    /// Return the entity private key in PEM format and the curve of the key.
    /// \return - The entity private key in PEM format and the curve of the key.
    std::pair<std::string, std::string> NanoTDFClient::getEntityPrivateKeyAndCurve() const {
        auto curveName =  ECCMode::GetEllipticCurveName(m_nanoTdfBuilder->m_impl->m_ellipticCurveType);
        return {m_nanoTdfBuilder->m_impl->m_privateKey, curveName};
    }

    /// Initialize the nano TDF builder which is used for creating the nano TDF
    /// instance used for encrypt and decrypt.
    void NanoTDFClient::initNanoTDFBuilder(bool newSDKKey) {

        Benchmark benchmark("Authentication and sdk setup time");

        auto oidcMode = m_nanoTdfBuilder->m_impl->m_oidcMode;
        auto entityObjectNotSet = m_nanoTdfBuilder->m_impl->m_entityObject.getUserId().empty();
        auto isOnlineMode = !m_nanoTdfBuilder->m_impl->m_offlineMode;

        auto keyNotSet = (m_nanoTdfBuilder->m_impl->m_privateKey.empty() ||
                m_nanoTdfBuilder->m_impl->m_publicKey.empty());

        if (keyNotSet || newSDKKey) {
            auto curveName = ECCMode::GetEllipticCurveName(m_nanoTdfBuilder->m_impl->m_ellipticCurveType);
            auto sdkECKeyPair = ECKeyPair::Generate(curveName);
            m_nanoTdfBuilder->m_impl->m_privateKey = sdkECKeyPair->PrivateKeyInPEMFormat();
            m_nanoTdfBuilder->m_impl->m_publicKey = sdkECKeyPair->PublicKeyInPEMFormat();
        }

        auto signerPrivateKeyIsNotSet = m_nanoTdfBuilder->m_impl->m_requestSignerPrivateKey.empty();
        auto signerPubicKeyIsNotSet = m_nanoTdfBuilder->m_impl->m_requestSignerPublicKey.empty();

        if (signerPrivateKeyIsNotSet || signerPubicKeyIsNotSet) {
            // Set the SDK signing key.
            auto curveName = ECCMode::GetEllipticCurveName(m_nanoTdfBuilder->m_impl->m_ellipticCurveType);
            auto ecKeyPair = ECKeyPair::Generate(curveName);
            m_nanoTdfBuilder->m_impl->m_requestSignerPrivateKey = ecKeyPair->PrivateKeyInPEMFormat();
            m_nanoTdfBuilder->m_impl->m_requestSignerPublicKey = ecKeyPair->PublicKeyInPEMFormat();
        }

        // Fetch entity object if it's online and entityObject is not set.
        if ((entityObjectNotSet &&  isOnlineMode) && !oidcMode) {
            fetchEntityObject();
        }

        std::string sdkRelease = "0.0.1";
        if (m_nanoTdfBuilder->m_impl->m_useOldNTDFFormat) {
            sdkRelease = "0.0.0";
        }

        HttpHeaders headers = {{kUserAgentKey, UserAgentValuePostFix},
                               {kVirtruClientKey, clientValue},
                               {kVirtruNTDFHeaderKey, sdkRelease}};

        auto networkServiceExpired = m_nanoTdfBuilder->m_impl->m_networkServiceProvider.expired();
        if (networkServiceExpired) {
            m_httpServiceProvider = std::make_shared<network::HTTPServiceProvider>();
            m_nanoTdfBuilder->setHttpHeaders(headers);
            m_nanoTdfBuilder->setHTTPServiceProvider(m_httpServiceProvider);
        }

        if (oidcMode) {
            LogDebug("Using OIDC auth mode");
            if (!m_oidcService) {
                m_oidcService = std::make_unique<OIDCService>(*m_oidcCredentials,
                                                              m_nanoTdfBuilder->m_impl->m_requestSignerPublicKey,
                                                              m_nanoTdfBuilder->m_impl->m_networkServiceProvider.lock());
            }

            auto authHeaders = m_oidcService->generateAuthHeaders();
            for (const auto& header: authHeaders) {
                headers.insert(header);
            }

            m_nanoTdfBuilder->m_impl->m_user = m_oidcService->getPreferredUsername();
            m_nanoTdfBuilder->setHttpHeaders(headers);
        }

        m_nanoTdfBuilder->enableConsoleLogging(m_logLevel);
    }

    /// Set the callback interface which will invoked for all the http network operations.
    void NanoTDFClient::setHTTPServiceProvider(std::weak_ptr<INetwork> httpServiceProvider) {
        LogTrace("NanoTDFClient::setHTTPServiceProvider");
        m_nanoTdfBuilder->setHTTPServiceProvider(httpServiceProvider);
    }

    /// Fetch EntityObject
    void NanoTDFClient::fetchEntityObject() {

        // Construct the headers.
        HttpHeaders headers = {{kContentTypeKey,    kContentTypeJsonValue},
                               {kAcceptKey,    kAcceptKeyValue},
                               {kUserAgentKey, UserAgentValuePostFix},
                               {kVirtruClientKey, clientValue}};

        // Construct the body for fetching the entity object.
        nlohmann::json publicKeyBody;
        publicKeyBody[kUserId] = m_user;
        publicKeyBody[kPublicKey] = m_nanoTdfBuilder->m_impl->m_publicKey;

        publicKeyBody[kAlgorithm] = kECDefaultAlgorithm;
        publicKeyBody[kSignerPublicKey] = m_nanoTdfBuilder->m_impl->m_requestSignerPublicKey;

        // Get the entity object
        auto entityObject = Utils::getEntityObject(m_easUrl, m_certAuthority, m_clientKeyFileName,
                                                   m_clientCertFileName, headers, to_string(publicKeyBody));

        m_nanoTdfBuilder->setEntityObject(entityObject).setHttpHeaders(headers);
    }

    /// Check if the file is in valid NanoTDF format.
    bool NanoTDFClient::isValidNanoTDFFile(const std::string& filePath) {
        return NanoTDFImpl::isValidNanoTDFFile(filePath);
    }

    /// Check if the data is in valid NanoTDF format.
    bool NanoTDFClient::isValidNanoTDFData(const std::string& nanoTDFData) {
        return NanoTDFImpl::isValidNanoTDFData(toBytes(nanoTDFData));
    }
}


