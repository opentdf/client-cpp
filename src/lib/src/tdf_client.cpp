/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/04/24
//

#include <cinttypes>

#include "attribute_object.h"
#include "crypto/ec_key_pair.h"
#include "crypto/rsa_key_pair.h"
#include "entity_object.h"
#include "logger.h"
#include "network_interface.h"
#include "sdk_constants.h"
#include "tdf_client_base.h"
#include "tdf_client.h"
#include "tdf.h"
#include "tdfbuilder.h"
#include "tdfbuilder_impl.h"
#include "oidc_service.h"
#include "utils.h"
#include "file_io_provider.h"
#include "stream_io_provider.h"
#include "s3_io_provider.h"
#include "benchmark.h"

#include <jwt-cpp/jwt.h>
#include <sstream>
#include <istream>
#include <fstream>
#include "nlohmann/json.hpp"

namespace virtru {

    //TODO: This need be changed.
    static const auto UserAgentValuePostFix = Utils::getUserAgentValuePostFix();
    static const auto VirtruClientValue = Utils::getClientValue();

    TDFClient::TDFClient(const std::string &backendUrl, const std::string &user)
            : TDFClient(backendUrl, user, "", "", "") {
        LogTrace("TDFClient::TDFClient(url,user)");
    }

    //NOTE this constructor shenaniganiry is for the purpose of maintaining back compat with
    //pre-OIDC flows (which required at a minimum an EAS URL and a username) and OIDC flows (which currently
    //require a KAS url and a username, though the former can be removed if we ship it as part of the token)
    TDFClient::TDFClient(const std::string &backendUrl, const std::string &user,
                           const std::string &clientKeyFileName, const std::string &clientCertFileName,
                           const std::string &sdkConsumerCertAuthority)
        : TDFClientBase(backendUrl, user, clientKeyFileName, clientCertFileName, sdkConsumerCertAuthority) {

        LogTrace("TDFClient::TDFClient(url,user,key,cert,ca)");
        m_tdfBuilder = std::make_unique<TDFBuilder>(m_user);
        m_tdfBuilder->setEasUrl(backendUrl);
    }

    /// Constructor
    /// \param oidcCredentials - OIDC credentials
    TDFClient::TDFClient(const OIDCCredentials& oidcCredentials, const std::string &kasUrl)
        :TDFClientBase(kasUrl, "", oidcCredentials.getClientKeyFileName(), oidcCredentials.getClientCertFileName(), oidcCredentials.getCertificateAuthority()) {
        LogTrace("TDFClient::TDFClient(cred,url)");
        m_tdfBuilder = std::make_unique<TDFBuilder>(oidcCredentials.getClientId());
        m_tdfBuilder->setKasUrl(kasUrl);
        m_tdfBuilder->enableOIDC(true);

        m_oidcCredentials = std::make_unique<OIDCCredentials>(oidcCredentials);
    }

    /// Destructor
    TDFClient::~TDFClient() = default;

    /// Assign the metadata that will be encrypted and stored in
    /// the TDF, separately from the data.
    void TDFClient::setEncryptedMetadata(const std::string& medata) {

        LogTrace("TDFClient::setEncryptedMetadata");

        m_metadata = medata;
    }

    /// Decrypt and return TDF metadata as a string. If the TDF content has
    /// no encrypted metadata, will return an empty string.
    std::string TDFClient::getEncryptedMetadata(const TDFStorageType &tdfStorageType) {

        LogTrace("TDFClient::getEncryptedMetadata");

        // Initialize the TDF builder
        initTDFBuilder();
        auto tdf = m_tdfBuilder->build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {

            // Create input provider
            FileInputProvider inputProvider{tdfStorageType.m_filePath};
            return tdf->getEncryptedMetadata(inputProvider);
        } else if(tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {

            // Create input provider
            std::istringstream inputStream(tdfStorageType.m_tdfBuffer);
            StreamInputProvider inputProvider{inputStream};
            return tdf->getEncryptedMetadata(inputProvider);
        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::S3) {

            // Create input provider
            S3InputProvider inputProvider{tdfStorageType.m_S3Url, tdfStorageType.m_awsAccessKeyId, tdfStorageType.m_awsSecretAccessKey, tdfStorageType.m_awsRegionName};

            return tdf->getEncryptedMetadata(inputProvider);
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        return {};
    }

    /// Encrypt the data by reading from inputProvider and writing to outputProvider.
    void TDFClient::encryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) {

        LogTrace("TDFClient::encryptWithIOProviders");

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();
        tdf->encryptIOProvider(inputProvider, outputProvider);
    }

    /// Decrypt the tdf data by reading from inputProvider and writing to outputProvider.
    void TDFClient::decryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) {

        LogTrace("TDFClient::decryptWithIOProviders");
        // Initialize the TDF builder
        initTDFBuilder();

        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();
        tdf->decryptIOProvider(inputProvider, outputProvider);
    }

    /// Encrypt the file to tdf format.
    void TDFClient::encryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) {
        LogTrace("TDFClient::encryptFile");

        Benchmark benchmark("Total encrypt file time:");

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();

        for (const auto& assertion: tdfStorageType.m_handlingAssertions) {
            m_tdfBuilder->setHandlingAssertion(assertion);
        }

        for (const auto& assertion: tdfStorageType.m_defaultAssertions) {
            m_tdfBuilder->setDefaultAssertion(assertion);
        }

        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {

            // Create input provider
            FileInputProvider inputProvider{tdfStorageType.m_filePath};

            // Create output provider
            FileOutputProvider outputProvider{outFilepath};
            tdf->encryptIOProvider(inputProvider, outputProvider);
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
    }

    /// Encrypt the bytes to tdf format.
    std::vector<VBYTE> TDFClient::encryptData(const TDFStorageType &tdfStorageType) {
        LogTrace("TDFClient::encryptData");

        Benchmark benchmark("Total encrypt data time");

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        for (const auto& assertion: tdfStorageType.m_handlingAssertions) {
            m_tdfBuilder->setHandlingAssertion(assertion);
        }

        for (const auto& assertion: tdfStorageType.m_defaultAssertions) {
            m_tdfBuilder->setDefaultAssertion(assertion);
        }

        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {

            // Create input provider
            std::istringstream inputStream(tdfStorageType.m_tdfBuffer);
            StreamInputProvider inputProvider{inputStream};

            // Create output provider
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};

            tdf->encryptIOProvider(inputProvider, outputProvider);

            std::string str = oStringStream.str();
            std::vector<VBYTE> buffer(str.begin(), str.end());
            return buffer;

        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            return {};
        }
    }

    /// Decrypt file to tdf file format.
    void TDFClient::decryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) {
        LogTrace("TDFClient::decryptFile");

        Benchmark benchmark("Total decrypt file time");

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        // TODO we really should drop the 'Builder' pattern here,
        // it accomplishes very little of use.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {

            // Create input provider
            FileInputProvider inputProvider{tdfStorageType.m_filePath};

            // Create output provider
            FileOutputProvider outputProvider{outFilepath};
            tdf->decryptIOProvider(inputProvider, outputProvider);
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
    }

    /// Decrypt the bytes to tdf format.
    std::vector<VBYTE> TDFClient::decryptData(const TDFStorageType &tdfStorageType) {
        LogTrace("TDFClient::decryptData");

        Benchmark benchmark("Total decrypt data time");

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        // TODO we really should drop the 'Builder' pattern here,
        // it accomplishes very little of use.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {

            // Create input provider
            FileInputProvider inputProvider{tdfStorageType.m_filePath};

            // Create output provider
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};

            tdf->decryptIOProvider(inputProvider, outputProvider);

            // TODO: Find a efficient way of copying data from stream
            std::string str = oStringStream.str();
            std::vector<VBYTE> buffer(str.begin(), str.end());
            return buffer;

        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {
            // Create input provider
            std::istringstream inputStream(tdfStorageType.m_tdfBuffer);
            StreamInputProvider inputProvider{inputStream};

            // Create output provider
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};

            tdf->decryptIOProvider(inputProvider, outputProvider);

            // TODO: Find a efficient way of copying data from stream
            std::string str = oStringStream.str();
            std::vector<VBYTE> buffer(str.begin(), str.end());
            return buffer;
        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::S3) {

            // Create input provider
            S3InputProvider inputProvider{tdfStorageType.m_S3Url, tdfStorageType.m_awsAccessKeyId, tdfStorageType.m_awsSecretAccessKey, tdfStorageType.m_awsRegionName};

            // Create output provider
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};

            tdf->decryptIOProvider(inputProvider, outputProvider);

            // TODO: Find a efficient way of copying data from stream
            std::string str = oStringStream.str();
            std::vector<VBYTE> buffer(str.begin(), str.end());
            return buffer;
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            return {};
        }
    }

    /// Decrypt part of the data of tdf storage type.
    std::vector<VBYTE> TDFClient::decryptDataPartial(const TDFStorageType &tdfStorageType, size_t offset, size_t length) {
        LogTrace("TDFClient::decryptPartial");

        Benchmark benchmark("Total decrypt data partial time");

        // Initialize the TDF builder
        initTDFBuilder();

        // NOTE: We don't require policy object for decrypting the TDF
        auto tdf = m_tdfBuilder->build();
        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {

            // Create input provider
            FileInputProvider inputProvider{tdfStorageType.m_filePath};

            // Create output provider
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};

            tdf->decryptIOProviderPartial(inputProvider, outputProvider, offset, length);

            // TODO: Find a efficient way of copying data from stream
            std::string str = oStringStream.str();
            std::vector<VBYTE> buffer(str.begin(), str.end());
            return buffer;

        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {
            // Create input provider
            std::istringstream inputStream(tdfStorageType.m_tdfBuffer);
            StreamInputProvider inputProvider{inputStream};

            // Create output provider
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};

            tdf->decryptIOProviderPartial(inputProvider, outputProvider, offset, length);

            // TODO: Find a efficient way of copying data from stream
            std::string str = oStringStream.str();
            std::vector<VBYTE> buffer(str.begin(), str.end());
            return buffer;
        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::S3) {

            // Create input provider
            S3InputProvider inputProvider{tdfStorageType.m_S3Url, tdfStorageType.m_awsAccessKeyId, tdfStorageType.m_awsSecretAccessKey, tdfStorageType.m_awsRegionName};

            // Create output provider
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};

            tdf->decryptIOProviderPartial(inputProvider, outputProvider, offset, length);

            // TODO: Find a efficient way of copying data from stream
            std::string str = oStringStream.str();
            std::vector<VBYTE> buffer(str.begin(), str.end());
            return buffer;
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            return {};
        }
    }

    /// Get the policy document as a JSON string from the encrypted TDF data.
    std::string TDFClient::getPolicy(const TDFStorageType &tdfStorageType) {
        LogTrace("TDFClient::getPolicy");

        // Initialize the TDF builder
        initTDFBuilder();
        auto tdf = m_tdfBuilder->build();

        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {

            // Create input provider
            FileInputProvider inputProvider{tdfStorageType.m_filePath};
            return tdf->getPolicy(inputProvider);
        } else if(tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {

            // Create input provider
            std::istringstream inputStream(tdfStorageType.m_tdfBuffer);
            StreamInputProvider inputProvider{inputStream};
            return tdf->getPolicy(inputProvider);
        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::S3) {

            // Create input provider
            S3InputProvider inputProvider{tdfStorageType.m_S3Url, tdfStorageType.m_awsAccessKeyId, tdfStorageType.m_awsSecretAccessKey, tdfStorageType.m_awsRegionName};

            return tdf->getPolicy(inputProvider);
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        return {};
    }

    ///Add data attribute
    void TDFClient::addDataAttribute(const std::string &dataAttribute, const std::string &kasURL) {
        LogTrace("TDFClient::addDataAttribute");

        std::string userKasURL{kasURL};
        if (userKasURL.empty()) {
            userKasURL = m_tdfBuilder->m_impl->m_kasUrl;
        }

        if (userKasURL != m_tdfBuilder->m_impl->m_kasUrl){
            LogWarn("Multi KAS is not supported");
        }

        std::string displayName;
        m_dataAttributeObjects.emplace_back(dataAttribute, displayName,
                                            m_tdfBuilder->m_impl->m_kasPublicKey, userKasURL);
    }

    //TODO C++ makes it extremely difficult so I gave up, but it should be possible to do TDFStorageType to
    //IInputProvider conversion centrally in a helper func, rather than copypaste this big conditional into
    //*every single place* in this class where we do it inline.
    bool TDFClient::isTDF(const TDFStorageType &tdfStorageType) {
        if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::File) {
            // Create input provider
            FileInputProvider inputProvider{tdfStorageType.m_filePath};
            return TDF::isInputProviderTDF(inputProvider);
        } else if(tdfStorageType.m_tdfType == TDFStorageType::StorageType::Buffer) {
            // Create input provider
            std::istringstream inputStream(tdfStorageType.m_tdfBuffer);
            StreamInputProvider inputProvider{inputStream};
            return TDF::isInputProviderTDF(inputProvider);
        } else if (tdfStorageType.m_tdfType == TDFStorageType::StorageType::S3) {

            // Create input provider
            S3InputProvider inputProvider{tdfStorageType.m_S3Url, tdfStorageType.m_awsAccessKeyId, tdfStorageType.m_awsSecretAccessKey, tdfStorageType.m_awsRegionName};
            return TDF::isInputProviderTDF(inputProvider);
        } else {
            std::string errorMsg{"Unknown TDF storage type"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            return false;
        }
    }

    //check if file is tdf
    bool TDFClient::isFileTDF(const std::string &inFilepath) {
        LogTrace("TDFClient::isFileTDF");

        FileInputProvider inputProvider{inFilepath};
        return TDF::isInputProviderTDF(inputProvider);
    }

    //check if string is tdf
    bool TDFClient::isStringTDF(const std::string &tdfString) {
        LogTrace("TDFClient::isStringTDF");

        std::istringstream inputStream(tdfString);
        StreamInputProvider inputProvider{inputStream};
        return TDF::isInputProviderTDF(inputProvider);
    }

    //check if data is tdf
    bool TDFClient::isDataTDF(const std::vector<VBYTE> &tdfData) {
        LogTrace("TDFClient::isDataTDF");

        std::string tdfString(tdfData.begin(), tdfData.end());
        std::istringstream inputStream(tdfString);
        StreamInputProvider inputProvider{inputStream};
        return TDF::isInputProviderTDF(inputProvider);
    }

    /// Convert the xml formatted TDF to the json formatted TDF
    void TDFClient::convertXmlToJson(const std::string& ictdfFilePath, const std::string& tdfFilePath) {

        LogTrace("TDFClient::convertToTDF");

        Benchmark benchmark("Total tdf conversion file time");
        TDF::convertXmlToJson(ictdfFilePath, tdfFilePath);
    }

    /// Convert the json formatted TDF to xml formatted TDF(ICTDF)
    void TDFClient::convertJsonToXml(const std::string& tdfFilePath, const std::string& ictdfFilePath) {

        LogTrace("TDFClient::convertJsonToXml");

        Benchmark benchmark("Total tdf conversion file time");
        TDF::convertJsonToXml(tdfFilePath, ictdfFilePath);
    }

    /// Initialize the TDF builder which is used for creating the TDF instance
    /// used for encrypt and decrypt.
    void TDFClient::initTDFBuilder() {
        LogTrace("TDFClient::initTDFBuilder");

        Benchmark benchmark("Authentication and sdk setup time");

        auto oidcMode = m_tdfBuilder->m_impl->m_oidcMode;
        auto entityObjectNotSet = m_tdfBuilder->m_impl->m_entityObject.getUserId().empty();
        m_tdfBuilder->setMetaDataAsJsonStr(m_metadata).setKeyAccessType(KeyAccessType::Wrapped);

        auto privateKeyIsNotSet = m_tdfBuilder->m_impl->m_privateKey.empty();
        auto pubicKeyIsNotSet = m_tdfBuilder->m_impl->m_publicKey.empty();

        constexpr auto defaultKeySize = 2048;
        if (privateKeyIsNotSet || pubicKeyIsNotSet) {

            // Create RSA key pair.
            auto keyPairOf2048 = crypto::RsaKeyPair::Generate(defaultKeySize);
            m_tdfBuilder->setPrivateKey(keyPairOf2048->PrivateKeyInPEMFormat())
                    .setPublicKey(keyPairOf2048->PublicKeyInPEMFormat());
        }

        auto signerPrivateKeyIsNotSet = m_tdfBuilder->m_impl->m_requestSignerPrivateKey.empty();
        auto signerPubicKeyIsNotSet = m_tdfBuilder->m_impl->m_requestSignerPublicKey.empty();

        if (signerPrivateKeyIsNotSet || signerPubicKeyIsNotSet) {
            // Set the SDK signing key.
            auto keyPairOf2048 = crypto::RsaKeyPair::Generate(defaultKeySize);
            m_tdfBuilder->m_impl->m_requestSignerPrivateKey = keyPairOf2048->PrivateKeyInPEMFormat();
            m_tdfBuilder->m_impl->m_requestSignerPublicKey = keyPairOf2048->PublicKeyInPEMFormat();
        }

        HttpHeaders headers = {{kUserAgentKey, UserAgentValuePostFix},
                               {kVirtruClientKey, VirtruClientValue}};

        auto networkServiceExpired = m_tdfBuilder->m_impl->m_networkServiceProvider.expired();
        if (networkServiceExpired) {
            m_httpServiceProvider = std::make_shared<network::HTTPServiceProvider>();
            m_tdfBuilder->setHttpHeaders(headers);
            m_tdfBuilder->setHTTPServiceProvider(m_httpServiceProvider);
        }

        //Deprecated/remove this case - not in OIDC mode, need to fetch Entity Object
        if (entityObjectNotSet && !oidcMode) {
            LogDebug("Using legacy auth mode");
            // Construct the body
            nlohmann::json publicKeyBody;
            publicKeyBody[kUserId] = m_user;
            publicKeyBody[kPublicKey] = m_tdfBuilder->m_impl->m_publicKey;

            // The default key size is 2048
            publicKeyBody[kAlgorithm] = "rsa:2048";

            // Get the entity object
            EntityObject entityObject{};
            entityObject = Utils::getEntityObject(m_easUrl, m_certAuthority,
                                                  m_clientKeyFileName, m_clientCertFileName, headers,
                                                  to_string(publicKeyBody));

            m_tdfBuilder->setEntityObject(entityObject);
        }

        //If we're using OIDC auth mode (upsert/rewrap V2) - then we ignore EOs
        //and assume that an Auth header has already been set
        if (oidcMode) {
            LogDebug("Using OIDC auth mode");
            if (!m_oidcService) {
                m_oidcService = std::make_unique<OIDCService>(*m_oidcCredentials,
                                                              m_tdfBuilder->m_impl->m_requestSignerPublicKey,
                                                              m_tdfBuilder->m_impl->m_networkServiceProvider.lock());
            }

            auto authHeaders = m_oidcService->generateAuthHeaders();
            for (const auto& header: authHeaders) {
                headers.insert(header);
            }

            m_tdfBuilder->m_impl->m_user = m_oidcService->getPreferredUsername();
            m_tdfBuilder->setHttpHeaders(headers);
        }
        m_tdfBuilder->enableConsoleLogging(m_logLevel);
    }

    /// Get vector of entity attribute objects
    std::vector<AttributeObject> TDFClient::getEntityAttrObjects() {
        LogTrace("TDFClient::getEntityAttrObjects");
        std::vector<AttributeObject> entityAttributesObjects;

        initTDFBuilder();
        std::vector<std::string> attributesAsJwt = m_tdfBuilder->m_impl->m_entityObject.getAttributesAsJWT();

        //for each attributeObj JWT in the JWT vector
        for (auto &attributeObj : attributesAsJwt) {
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
    std::vector<AttributeObject> TDFClient::getSubjectAttrObjects() {

        LogTrace("TDFClient::getSubjectAttrObjects");
        std::vector<AttributeObject> subjectAttributesObjects;
        initTDFBuilder();
        auto attributes = m_oidcService->getClaimsObjectAttributes();

        subjectAttributesObjects.reserve(attributes.size());
        std::string emptyDisplayName;
        for (auto& attribute : attributes) {
            subjectAttributesObjects.emplace_back(AttributeObject {attribute,
                                                                   emptyDisplayName,
                                                                   m_tdfBuilder->m_impl->m_kasPublicKey,
                                                                   m_tdfBuilder->m_impl->m_kasUrl,
                                                                   false});
        }

        return subjectAttributesObjects;
    }

    /// Set the callback interface which will invoked for all the http network operations.
    void TDFClient::setHTTPServiceProvider(std::weak_ptr<INetwork> httpServiceProvider) {
        LogTrace("TDFClient::setHTTPServiceProvider");
        m_tdfBuilder->setHTTPServiceProvider(httpServiceProvider);
    }

    /// Create TDFs in XML format instead of zip format.
    void TDFClient::setXMLFormat() {
        LogTrace("TDFClient::setXMLFormat");
        m_tdfBuilder->setProtocol(Protocol::Xml);
    }

    /// Set the private key(In PEM format), which will be used by this SDK for encryption/decryption of the payload.
    void TDFClient::setPrivateKey(const std::string& privateKey) {
        LogTrace("TDFClient::setPrivateKey");
        m_tdfBuilder->setPrivateKey(privateKey);
    }

    /// Set the public key(In PEM format), which will be used by this SDK for encryption/decryption of the payload.
    void TDFClient::setPublicKey(const std::string& publicKey) {
        LogTrace("TDFClient::setPublicKey");
        m_tdfBuilder->setPublicKey(publicKey);
    }
} // namespace virtru
