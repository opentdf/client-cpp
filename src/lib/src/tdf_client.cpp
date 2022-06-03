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
    std::string TDFClient::getEncryptedMetadata(const std::string &tdfData) {

        LogTrace("TDFClient::getEncryptedMetadata");

        // Initialize the TDF builder
        initTDFBuilder();

        std::istringstream inputStream(tdfData);

        auto tdf = m_tdfBuilder->build();
        return tdf->getEncryptedMetadata(inputStream);
    }

    /// Encrypt the file to tdf format.
    void TDFClient::encryptFile(const std::string &inFilepath, const std::string &outFilepath) {

        LogTrace("TDFClient::encryptFile");
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();
        tdf->encryptFile(inFilepath, outFilepath);
    }

    /// Encrypt the data to tdf format.
    std::string TDFClient::encryptString(const std::string &plainData) {
        LogTrace("TDFClient::encryptString");

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::istringstream inputStream(plainData);
        std::ostringstream ioStream;

        // encrypt the stream.
        tdf->encryptStream(inputStream, ioStream);

        return ioStream.str();
    }

    /// Encrypt the bytes to tdf format.
    std::vector<VBYTE> TDFClient::encryptData(const std::vector<VBYTE> &plainData) {
        LogTrace("TDFClient::encryptData");
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::stringstream inputStream;
        inputStream.write(reinterpret_cast<const char *>(plainData.data()), plainData.size());

        // encrypt the stream.
        std::ostringstream ioStream;
        tdf->encryptStream(inputStream, ioStream);

        // NOTE: This is not efficient it makes a copy of internal buffer.
        const std::string& str = ioStream.str();
        std::vector<VBYTE> encryptedData(str.begin(), str.end());
        return encryptedData;
    }

    /// Decrypt file.
    void TDFClient::decryptFile(const std::string &inFilepath, const std::string &outFilepath) {

        LogTrace("TDFClient::decryptFile");
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        // TODO we really should drop the 'Builder' pattern here,
        // it accomplishes very little of use.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();
        tdf->decryptFile(inFilepath, outFilepath);
    }

    /// Decrypt data from tdf format.
    std::string TDFClient::decryptString(const std::string &encryptedData) {
        LogTrace("TDFClient::decryptString");
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        // TODO we really should drop the 'Builder' pattern here,
        // it accomplishes very little of use.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::istringstream inputStream(encryptedData);
        std::ostringstream ioStream;

        // encrypt the stream.
        tdf->decryptStream(inputStream, ioStream);

        return ioStream.str();
    }

    std::string TDFClient::decryptStringPartial(const std::string &encryptedData, size_t offset, size_t length) {
        LogTrace("TDFClient::decryptStringPartial");

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        // TODO we really should drop the 'Builder' pattern here,
        // it accomplishes very little of use.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::istringstream inputStream(encryptedData);
        std::ostringstream ioStream;

        // encrypt the stream.
        tdf->decryptStreamPartial(inputStream, ioStream, offset, length);

        return ioStream.str();
    }

    /// Decrypt the bytes from tdf format.
    std::vector<VBYTE> TDFClient::decryptData(const std::vector<VBYTE> &encryptedData) {
        LogTrace("TDFClient::decryptData");
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        // TODO we really should drop the 'Builder' pattern here,
        // it accomplishes very little of use.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::stringstream inputStream;
        inputStream.write(reinterpret_cast<const char *>(encryptedData.data()), encryptedData.size());

        // decrypt the stream.
        std::ostringstream ioStream;
        tdf->decryptStream(inputStream, ioStream);

        // NOTE: This is not efficient it makes a copy of internal buffer.
        const std::string& str = ioStream.str();
        std::vector<VBYTE> plainData(str.begin(), str.end());
        return plainData;
    }

    /// Get the policy document as a JSON string from the encrypted TDF data.
    std::string TDFClient::getPolicy(const std::string &encryptedData) {
        LogTrace("TDFClient::getPolicy");
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object - note that this has nothing to do with the policy
        // we will get and return, this is just an empty object we hand to the builder
        // so the builder will give us the TDF interface we want to do the thing we want
        // to do.
        // TODO we really should drop the 'Builder' pattern here,
        // it accomplishes very little of use.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::istringstream inputStream(encryptedData);

        // return the policy.
        return tdf->getPolicy(inputStream);
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

    //check if file is tdf
    bool TDFClient::isFileTDF(const std::string &inFilepath) {
        LogTrace("TDFClient::isFileTDF");

        // Open the input file for reading.
        std::ifstream inStream{inFilepath, std::ios_base::in | std::ios_base::binary};
        if (!inStream) {
            std::string errorMsg{"Failed to open file for reading:"};
            errorMsg.append(inFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        return TDF::isStreamTDF(inStream);
    }

    //check if string is tdf
    bool TDFClient::isStringTDF(const std::string &tdfString) {
        LogTrace("TDFClient::isStringTDF");
 
        // NOTE: look into pubsetbuf for better performance.
        std::istringstream inputStream(tdfString);

        return TDF::isStreamTDF(inputStream);
    }

    //check if data is tdf
    bool TDFClient::isDataTDF(const std::vector<VBYTE> &tdfData) {
        LogTrace("TDFClient::isDataTDF");
 
        // NOTE: look into pubsetbuf for better performance.
        std::stringstream inputStream;
        inputStream.write(reinterpret_cast<const char *>(tdfData.data()), tdfData.size());

        return TDF::isStreamTDF(inputStream);
    }

    /// Initialize the TDF builder which is used for creating the TDF instance
    /// used for encrypt and decrypt.
    void TDFClient::initTDFBuilder() {
        LogTrace("TDFClient::initTDFBuilder");

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
