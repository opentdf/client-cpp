//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/04/24
//  Copyright 2020 Virtru Corporation
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
#include "nlohmann/json.hpp"

namespace virtru {

    //TODO: This need be changed.
    constexpr auto UserAgentValuePostFix = "Openstack C++ SDK v0.1";
    constexpr auto VirtruClientValue = "openstack-cpp-sdk:0.0.0";

    TDFClient::TDFClient(const std::string &backendUrl, const std::string &user)
            : TDFClient(backendUrl, user, "", "", "") {
    }

    //NOTE this constructor shenaniganiry is for the purpose of maintaining back compat with
    //pre-OIDC flows (which required at a minimum an EAS URL and a username) and OIDC flows (which currently
    //require a KAS url and a username, though the former can be removed if we ship it as part of the token)
    TDFClient::TDFClient(const std::string &backendUrl, const std::string &user,
                           const std::string &clientKeyFileName, const std::string &clientCertFileName,
                           const std::string &sdkConsumerCertAuthority)
        : TDFClientBase(backendUrl, user, clientKeyFileName, clientCertFileName, sdkConsumerCertAuthority) {

        m_tdfBuilder = std::make_unique<TDFBuilder>(m_user);
        m_tdfBuilder->setEasUrl(backendUrl);
    }

    /// Constructor
    /// \param oidcCredentials - OIDC credentials
    TDFClient::TDFClient(const OIDCCredentials& oidcCredentials, const std::string &kasUrl)
        :TDFClientBase(kasUrl, "", "", "", "") {
        m_tdfBuilder = std::make_unique<TDFBuilder>(oidcCredentials.getClientId());
        m_tdfBuilder->setKasUrl(kasUrl);
        m_tdfBuilder->enableOIDC(true);

        m_oidcCredentials = std::make_unique<OIDCCredentials>(oidcCredentials);
    }

    /// Destructor
    TDFClient::~TDFClient() = default;

    /// Encrypt the file to tdf format.
    void TDFClient::encryptFile(const std::string &inFilepath, const std::string &outFilepath) {

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();
        tdf->encryptFile(inFilepath, outFilepath);
    }

    /// Encrypt the data to tdf format.
    std::string TDFClient::encryptString(const std::string &plainData) {

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

        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();
        tdf->decryptFile(inFilepath, outFilepath);
    }

    /// Decrypt data from tdf format.
    std::string TDFClient::decryptString(const std::string &encryptedData) {
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::istringstream inputStream(encryptedData);
        std::ostringstream ioStream;

        // encrypt the stream.
        tdf->decryptStream(inputStream, ioStream);

        return ioStream.str();
    }

    /// Decrypt the bytes from tdf format.
    std::vector<VBYTE> TDFClient::decryptData(const std::vector<VBYTE> &encryptedData) {
        // Initialize the TDF builder
        initTDFBuilder();

        // Create a policy object.
        auto policyObject = createPolicyObject();
        auto tdf = m_tdfBuilder->setPolicyObject(policyObject).build();

        // NOTE: look into pubsetbuf for better performance.
        std::stringstream inputStream;
        inputStream.write(reinterpret_cast<const char *>(encryptedData.data()), encryptedData.size());

        // encrypt the stream.
        std::ostringstream ioStream;
        tdf->decryptStream(inputStream, ioStream);

        // NOTE: This is not efficient it makes a copy of internal buffer.
        const std::string& str = ioStream.str();
        std::vector<VBYTE> plainData(str.begin(), str.end());
        return plainData;
    }

    /// Initialize the TDF builder which is used for creating the TDF instance
    /// used for encrypt and decrypt.
    void TDFClient::initTDFBuilder() {

        auto oidcMode = m_tdfBuilder->m_impl->m_oidcMode;
        auto entityObjectNotSet = m_tdfBuilder->m_impl->m_entityObject.getUserId().empty();

        auto privateKeyIsNotSet = m_tdfBuilder->m_impl->m_privateKey.empty();
        auto pubicKeyIsNotSet = m_tdfBuilder->m_impl->m_publicKey.empty();

        constexpr auto defaultKeySize = 2048;
        if (privateKeyIsNotSet || pubicKeyIsNotSet) {

            // Create RSA key pair.
            auto keyPairOf2048 = crypto::RsaKeyPair::Generate(defaultKeySize);
            m_tdfBuilder->setKeyAccessType(KeyAccessType::Wrapped)
                    .setPrivateKey(keyPairOf2048->PrivateKeyInPEMFormat())
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

        HttpHeaders headers = {{kContentTypeKey, kContentTypeJsonValue},
                               {kAcceptKey, kAcceptKeyValue},
                               {kUserAgentKey, UserAgentValuePostFix},
                               {kVirtruClientKey, VirtruClientValue}};

        //If we're using OIDC auth mode (upsert/rewrap V2) - then we ignore EOs
        //and assume that an Auth header has already been set
        if (entityObjectNotSet && !oidcMode) {

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

            m_tdfBuilder->enableConsoleLogging(m_logLevel)
                    .setHttpHeaders(headers);
        }

        if (oidcMode) {

            if (!m_oidcService) {
                HttpHeaders oidcHeaders = {{kUserAgentKey,    UserAgentValuePostFix}};
                m_oidcService = std::make_unique<OIDCService>(*m_oidcCredentials,
                                                              oidcHeaders,
                                                              m_tdfBuilder->m_impl->m_requestSignerPublicKey);
            }

            auto authHeaders = m_oidcService->generateAuthHeaders();
            for (const auto& header: authHeaders) {
                headers.insert(header);
            }

            m_tdfBuilder->m_impl->m_user = m_oidcService->getPreferredUsername();
            m_tdfBuilder->enableConsoleLogging(m_logLevel)
                    .setHttpHeaders(headers);
            }
        }

    /// Get vector of entity attribute objects
    std::vector<AttributeObject> TDFClient::getEntityAttrObjects() {
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

    /// Create TDFs in XML format instead of zip format.
    void TDFClient::setXMLFormat() {
        m_tdfBuilder->setProtocol(Protocol::Xml);
    }
} // namespace virtru
