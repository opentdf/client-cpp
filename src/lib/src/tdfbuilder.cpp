/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/27.
//

#include "tdfbuilder.h"
#include "attribute_objects_cache.h"
#include "tdfbuilder_impl.h"
#include "utils.h"

#include <fstream>
#include "nlohmann/json.hpp"

namespace virtru {
    /// Constructor
    TDFBuilder::TDFBuilder(const std::string &user)
        : m_impl(std::make_unique<TDFBuilderImpl>(user)) {
    }

    /// Set the kas url that will be used for tdf operations.
    /// \param kasUrl - The kas(Key Access Server) url(ex: api-develop01.develop.virtru.com).
    /// \return - Return a reference of this instance.
    TDFBuilder &TDFBuilder::setKasUrl(const std::string &kasUrl) {

        // TODO: Validate the url

        m_impl->m_kasUrl = kasUrl;

        return *this;
    }

    /// Set the user to a value other than what was specified in the constructor
    /// \param user  - new value of user
    /// \return - Return a reference of this instance.
    TDFBuilder &TDFBuilder::setUser(const std::string &user) {

        LogTrace("setUser");
        LogDebug("user=" + user);
        // TODO: Validate the user

        m_impl->m_user = user;

        return *this;
    }

    /// Set the eas url that will be used for tdf operations.
    /// \param easUrl - The eas(Entity Attribute Server) url.
    /// \return - Return a reference of this instance.
    TDFBuilder &TDFBuilder::setEasUrl(const std::string &easUrl) {

        // TODO: Validate the url

        m_impl->m_easUrl = easUrl;

        return *this;
    }

    /// Set the http headers which will be used for all the http network operations.
    TDFBuilder &TDFBuilder::setHttpHeaders(const std::unordered_map<std::string, std::string> &headers) {

        m_impl->m_httpHeaders = headers;

        return *this;
    }

    /// TODO this has no business being in the Builder, but the builder pattern
    /// is largely pointless versus TDFClient as it is just a bunch of duplicated
    /// setter funcs and a `validate()` call
    /// Set the callback interface which will invoked for all the http network operations.
    TDFBuilder &TDFBuilder::setHTTPServiceProvider(std::weak_ptr<INetwork> httpServiceProvider) {
        LogTrace("TDFBuilder::setHTTPServiceProvider");
        m_impl->m_networkServiceProvider = std::move(httpServiceProvider);
        return *this;
    }

    /// Return a unique ptr of TDF object. This can be use to exercise operation like
    /// encryption/decryption of the payload.
    std::unique_ptr<TDF> TDFBuilder::build() {

        // validate the data before constructing TDF instance.
        validate();

        return std::unique_ptr<TDF>(new TDF(*this));
    }

    /// Set the private key(In PEM format), which will be used by this SDK for encryption/decryption of the payload.
    TDFBuilder &TDFBuilder::setPrivateKey(const std::string &privateKey) {

        m_impl->m_privateKey = privateKey;

        return *this;
    }

    /// Set the public key(In PEM format), which will be used by this SDK for encryption/decryption of the payload.
    TDFBuilder &TDFBuilder::setPublicKey(const std::string &publicKey) {

        m_impl->m_publicKey = publicKey;

        return *this;
    }

    /// Sets the default size of each segment while performing encryption/decryption of the payload.
    TDFBuilder &TDFBuilder::setDefaultSegmentSize(unsigned int segmentSize) {

        m_impl->m_segmentSize = segmentSize;

        return *this;
    }

    /// Set the policy object on the TDF instance.
    TDFBuilder &TDFBuilder::setPolicyObject(const PolicyObject &policyObject) {

        m_impl->m_policyObject = policyObject;

        return *this;
    }

    /// Set the encryption Object on the TDF instance.
    TDFBuilder &TDFBuilder::setEncryptionObject(KeyType keyType, CipherType cipherType) {

        m_impl->m_keyType = keyType;
        m_impl->m_cipherType = cipherType;

        return *this;
    }

    /// Sets the integrity algorithm and segment integrity algorithms onto a TDF instance.
    TDFBuilder &TDFBuilder::setIntegrityAlgorithm(IntegrityAlgorithm integrityAlgorithm,
                                                    IntegrityAlgorithm segmentIntegrityAlgorithm) {

        m_impl->m_integrityAlgorithm = integrityAlgorithm;
        m_impl->m_segmentIntegrityAlgorithm = segmentIntegrityAlgorithm;

        return *this;
    }

    /// Sets the key access type.
    TDFBuilder &TDFBuilder::setKeyAccessType(KeyAccessType keyAccessType) {

        m_impl->m_keyAccessType = keyAccessType;

        return *this;
    }

    /// Set the kas public key(In PEM format)
    TDFBuilder &TDFBuilder::setKasPublicKey(const std::string &kasPublicKey) {

        m_impl->m_kasPublicKey = kasPublicKey;

        return *this;
    }

    /// Enable OIDC mode
    TDFBuilder &TDFBuilder::enableOIDC(bool enableOIDC) {

        m_impl->m_oidcMode = enableOIDC;

        return *this;
    }

    /// Set the key access object. TDF can have multiple key access object. However they all should have
    /// the same 'KeyAccessType'
    TDFBuilder &TDFBuilder::setKeyAccessObject(const KeyAccessObject &keyAccessObject) {

        if (!m_impl->m_keyAccessObjects.empty()) {
            auto &obj = m_impl->m_keyAccessObjects[0];

            // TODO: should check if they have same kas url and public key??

            if (obj.getKeyAccessType() != keyAccessObject.getKeyAccessType()) {
                ThrowException("All the key access objects should have the same 'KeyAccess' type.");
            }
        }

        m_impl->m_keyAccessObjects.push_back(keyAccessObject);

        return *this;
    }

    /// Set the protocol to be used for encryption and decryption.
    TDFBuilder &TDFBuilder::setProtocol(Protocol protocol) {

        m_impl->m_protocol = protocol;

        return *this;
    }

    /// Set the secure reader url which will be used in html tdf.
    TDFBuilder &TDFBuilder::setSecureReaderURL(const std::string &url) {

        m_impl->m_secureReaderUrl = url;

        return *this;
    }

    /// Set the html template file path, this sdk will look for these placeholders(<%= dataInput %>,
    /// <%= dataManifest %>, <%= url %>) and replace with tdf data.
    TDFBuilder &TDFBuilder::setHtmlTemplateFilepath(const std::string &htmlTemplateFilePath) {

        /// Read html template file.
        std::string htmlTemplateData;
        std::ifstream ifs(htmlTemplateFilePath.data(), std::ios::binary | std::ios::ate);
        if (!ifs) {
            std::string errorMsg{"Failed to open file for reading - "};
            errorMsg.append(htmlTemplateFilePath);
            ThrowException(std::move(errorMsg));
        }

        std::ifstream::pos_type fileSize = ifs.tellg();
        htmlTemplateData.reserve(fileSize);
        ifs.seekg(0, std::ios::beg);
        htmlTemplateData.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());

        return setHtmlTemplateData(std::move(htmlTemplateData));
    }

    /// Set the html template data, sdk will look for these placeholders(<%= dataInput %>,
    /// <%= dataManifest %>, <%= url %>) and replace with tdf data.
    TDFBuilder &TDFBuilder::setHtmlTemplateData(std::string htmlTemplateData) {

        std::vector<std::string> placeholders{"<%= payload %>", "<%= manifest %>",
                                              "<%= transferUrl %>", "<%= transferBaseUrl %>",
                                              "<%= transferUrl %>", "<%= transferUrl %>"};

        m_impl->m_htmlTemplateTokens.clear();

        // Split the html template into tokens.
        for (auto const &placeholder : placeholders) {
            size_t placeholderPos = htmlTemplateData.find(placeholder);
            if (placeholderPos == std::string::npos) {
                std::string errorMsg{placeholder};
                errorMsg.append(" not found in the html template.");
                ThrowException(std::move(errorMsg));
            }

            m_impl->m_htmlTemplateTokens.emplace_back(htmlTemplateData.substr(0, placeholderPos));
            htmlTemplateData.erase(0, placeholderPos + placeholder.length());
        }
        m_impl->m_htmlTemplateTokens.emplace_back(htmlTemplateData);

        if (m_impl->m_htmlTemplateTokens.size() != placeholders.size() + 1) {
            ThrowException("Invalid html tokens size.");
        }

        return *this;
    }

    /// Set the MIME type of the tdf payload. If not set default mime type is
    /// assumed("application/octet-stream")
    TDFBuilder &TDFBuilder::setPayloadMimeType(const std::string &mimeType) {

        m_impl->m_mimeType = mimeType;

        return *this;
    }

    /// Set the entity object. This can be used for offline mode.
    TDFBuilder &TDFBuilder::setEntityObject(const EntityObject &entityObject) {

        m_impl->m_entityObject = entityObject;

        return *this;
    }

    /// Set any meta data information than be leveraged by KAS/EAS server.
    TDFBuilder &TDFBuilder::setMetaData(const std::unordered_map<std::string, std::string> &properties) {

        const nlohmann::json metaData = properties;

        std::string metaDataAsJsonStr = to_string(metaData);

        LogDebug("Meta data: " + metaDataAsJsonStr);
        m_impl->m_metadataAsJsonStr = metaDataAsJsonStr;

        return *this;
    }

    /// Set any meta data information than be leveraged by KAS/EAS server.
    TDFBuilder &TDFBuilder::setMetaDataAsJsonStr(const std::string &propertiesAsJsonStr) {

        m_impl->m_metadataAsJsonStr = propertiesAsJsonStr;

        return *this;
    }

    /// Enable the logger to write logs to the console.
    TDFBuilder &TDFBuilder::enableConsoleLogging(LogLevel logLevel) {

        Logger::getInstance().setLogLevel(logLevel);
        Logger::getInstance().enableConsoleLogging();

        return *this;
    }

    /// Set the external logger.
    TDFBuilder &TDFBuilder::setExternalLogger(std::shared_ptr<ILogger> externalLogger, LogLevel logLevel) {

        Logger::getInstance().setLogLevel(logLevel);
        Logger::getInstance().setExternalLogger(std::move(externalLogger));

        return *this;
    }

    /// Set the cert authority which will be used in SSL handshake for all the network I/O..
    TDFBuilder &TDFBuilder::setCertAuthority(const std::string &certAuthority) {

        m_impl->m_rootCAs = std::move(certAuthority);

        // TODO: Not implemented yet
        LogError("TDFBuilder::setCertAuthority - NOT IMPLEMENTED");

        return *this;
    }

    /// Set the cert authority which will be used in SSL handshake for all the network I/O.
    TDFBuilder &TDFBuilder::setCertAuthority(std::string &&certAuthority) noexcept {

        m_impl->m_rootCAs = std::move(certAuthority);

        // TODO: Not implemented yet
        LogError("TDFBuilder::setCertAuthority - NOT IMPLEMENTED");

        return *this;
    }

    ///Access the entity object (needed to give access to client - m_impl is private)
    EntityObject &TDFBuilder::getEntityObject() const {
        return m_impl->m_entityObject;
    }

    /// TODO this has no business being in the Builder, but the builder pattern
    /// is largely pointless versus TDFClient as it is just a bunch of duplicated
    /// setter funcs and a `validate()` call
    /// Returns a network provider for making HTTP calls with.
    /// If no provider was externally supplied with `setHTTPServiceProvider`, a new one
    /// will be created and configured with `defaultHeaders`
    std::shared_ptr<INetwork> TDFBuilder::getHTTPServiceProvider(HttpHeaders defaultHeaders) const {
        if (auto sp = m_impl->m_networkServiceProvider.lock()) {
            LogDebug("Using existing network provider");
            return sp;
        } else {
            LogDebug("No network provider defined, creating one...");
            // No service provided, create one using supplied headers
            std::shared_ptr<INetwork> httpServiceProvider =
                std::make_shared<network::HTTPServiceProvider>(defaultHeaders);
            return httpServiceProvider;
        }
    }

    /// Destructor
    TDFBuilder::~TDFBuilder() = default;

    /// Validate the data set by the consumer of the TDFBuilder
    void TDFBuilder::validate() {
        ///
        // Set the rsa key pair if they are not set.
        ///
        auto privateKeyIsSet = !m_impl->m_privateKey.empty();
        auto pubicKeyIsSet = !m_impl->m_publicKey.empty();

        if (privateKeyIsSet != pubicKeyIsSet) {
            ThrowException("Both private and public key must be set.");
        } else if (!pubicKeyIsSet && !privateKeyIsSet) {
            auto keyPairOf2048 = crypto::RsaKeyPair::Generate(2048);
            m_impl->m_privateKey = keyPairOf2048->PrivateKeyInPEMFormat();
            m_impl->m_publicKey = keyPairOf2048->PublicKeyInPEMFormat();
        }

        ///
        // Set the rsa key pair for signing the requests, if they are not set.
        ///
        auto signingPrivateKeyIsSet = !m_impl->m_requestSignerPrivateKey.empty();
        auto signingPubicKeyIsSet = !m_impl->m_requestSignerPublicKey.empty();

        if (signingPrivateKeyIsSet != signingPubicKeyIsSet) {
            ThrowException("Both signing private and public key must be set.");
        } else if (!signingPubicKeyIsSet && !signingPrivateKeyIsSet) {
            auto keyPairOf2048 = crypto::RsaKeyPair::Generate(2048);
            m_impl->m_requestSignerPrivateKey = keyPairOf2048->PrivateKeyInPEMFormat();
            m_impl->m_requestSignerPublicKey = keyPairOf2048->PublicKeyInPEMFormat();
        }

        // When using OIDC mode, EO and EAS are not set and should not be assumed.
        if (m_impl->m_oidcMode) {
            LogDebug("Establishing EO and EAS for OIDC");
            if (m_impl->m_kasUrl.empty()) {
                ThrowException("KAS URL must be set in OIDC mode");
            }
            if (m_impl->m_kasPublicKey.empty()) {
                auto kasKeyUrl = m_impl->m_kasUrl + kKasPubKeyPath;
                LogDebug("KAS public key was not set, fetching from provided KAS URL: " + kasKeyUrl);
                auto kasPublicKey = Utils::getKasPubkeyFromURLsp(kasKeyUrl, getHTTPServiceProvider({}));
                LogDebug("KAS public key fetched");
                m_impl->m_kasPublicKey = kasPublicKey;
            }
            if (!m_impl->m_easUrl.empty()) {
                LogWarn("EAS URL is deprecated, and ignored in OIDC mode.");
            }
            if (!m_impl->m_entityObject.getUserId().empty()) {
                LogWarn("EAS entityObjects are deprecated, and ignored in OIDC mode");
            }
            // Legacy EO/EAS mode
        } else {
            if (m_impl->m_easUrl.empty()) {
                ThrowException("No eas url is defined.");
            }

            // If the kas public key is missing, get it from the enity object.
            if (m_impl->m_kasPublicKey.empty()) {

                AttributeObjectsCache attributeObjectsCache{m_impl->m_entityObject};

                if (!attributeObjectsCache.hasDefaultAttribute()) {
                    ThrowException("Default attribute missing from the entity object.");
                }

                auto attributeObject = attributeObjectsCache.getDefaultAttributeObject();
                m_impl->m_kasPublicKey = attributeObject.getKasPublicKey();
                m_impl->m_kasUrl = attributeObject.getKasBaseUrl();
            }

            if (m_impl->m_entityObject.getUserId().empty()) {
                ThrowException("Entity object is missing.");
            }
        }
        // Build key access object.
        if (m_impl->m_keyAccessObjects.empty()) {

            if (m_impl->m_kasUrl.empty()) {
                ThrowException("No kas url is defined.");
            }

            auto keyAccessObject = KeyAccessObject{};
            keyAccessObject.setKasUrl(m_impl->m_kasUrl);
            keyAccessObject.setKeyAccessType(m_impl->m_keyAccessType);
            m_impl->m_keyAccessObjects.push_back(std::move(keyAccessObject));
        }

        // Check if secure reader url is set for html protocol.
        if (m_impl->m_protocol == Protocol::Html && m_impl->m_secureReaderUrl.empty()) {
            ThrowException("Secure reader url is missing for html protocol.");
        }

        // TODO: May be want to change to debug after production ready.
        LogInfo(m_impl->toString());
    }
} // namespace virtru
