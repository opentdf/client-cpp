/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/25.
//

#ifndef VIRTRU_TDFBUILDER_H
#define VIRTRU_TDFBUILDER_H

#include "tdf_constants.h"
#include "network_interface.h"

#include <memory>
#include <string>
#include <unordered_map>

namespace virtru {

    ///
    /// NOTE: User of this SDK has to catch virtru::exception. This sdk throws exception if any of the interfaces are
    /// not used or not configured correctly.
    ///

    /// Forward declaration.
    class PolicyObject;
    class KeyAccessObject;
    class EntityObject;
    class TDF;
    class TDFImpl;
    class ILogger;
    class TDFBuilderImpl;
    class INetwork;
    class TDFClient;

    /// Detail documentation - https://developer.virtru.com/docs/architecture
    class TDFBuilder {
    public: /// Interface MUST required by consumer by SDK.
        /// Constructor
        /// \param user - The user of this TDF creation process(ex:someuser@example.com)
        /// NOTE: The user specified for this instance is not the owner of the TDF, and
        /// will not automatically have access to the TDF. Only the users listed in
        /// the policy object will have access to the TDF.
        explicit TDFBuilder(const std::string& user);

        /// Set the kas url that will be used for tdf operations.
        /// \param kasUrl - The kas(Key Access Server) url(ex: api-develop01.develop.virtru.com).
        /// \return - Return a reference of this instance.
        TDFBuilder& setKasUrl(const std::string& kasUrl);

        /// Feature flag for OIDC-based auth flows
        /// In this mode, EOs are not used and EAS is not called
        /// Additionally, KAS requests will be different.
        /// \return - Return a reference of this instance.
        TDFBuilder& enableOIDC(bool enableOIDC);

        /// Set the eas url that will be used for tdf operations.
        /// \param easUrl - The eas(Entity Attribute Server) url.
        /// \return - Return a reference of this instance.
        TDFBuilder& setEasUrl(const std::string& easUrl);

        /// Set the kas public key(In PEM format)
        /// \param publicKey - The PEM-encoded kas public key as a string.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, this will be needed if the KeyAccessType is 'Wrapped'(offline mode)
        TDFBuilder& setKasPublicKey(const std::string& kasPublicKey);

        /// Set the entity object. This can be used for offline mode.
        /// \param entityObject - The key access type.
        /// \return - Return a reference of this instance.
        TDFBuilder& setEntityObject(const EntityObject& entityObject);

        /// Set the policy object on the TDF instance.
        /// \param policyObject - The policy object.
        /// \return - Return a reference of this instance.
        TDFBuilder& setPolicyObject(const PolicyObject& policyObject);

        /// Set the user on the TDF instance.
        /// \param user - The value to use instead of what was specified on the constructor.
        /// \return - Return a reference of this instance.
        TDFBuilder& setUser(const std::string& user);

        ///Get the entity object.
        /// \return - Return a reference to the entity object
        EntityObject& getEntityObject() const;

        /// Return a unique ptr of TDF object. This can be use to exercise operation like
        /// encryption/decryption of the payload.
        /// \return - Unique ptr of the TDF instance.
        /// NOTE: Throws an virtru::exception if any of the information is missing for construction of the TDF object.
        std::unique_ptr<TDF> build();

    public: /// Network I/O

        /// Set the http headers will be used for all the all the http network operations.
        /// \param properties - A unordered map holder the http headers.
        /// \return - Unique ptr of the TDF instance.
        TDFBuilder& setHttpHeaders(const std::unordered_map<std::string, std::string>& headers);

    public:
        /// Optional - Meta data

        /// Set any meta data information than be leveraged by KAS/EAS server.
        /// \param properties - A simple map containing key-values(strings) of properties to add to the metadata.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface. If the meta is more complex use 'setMetaDataAsJsonStr'
        TDFBuilder& setMetaData(const std::unordered_map<std::string, std::string>& properties);

        /// Set any meta data information than be leveraged by KAS/EAS server.
        /// \param propertiesAsJsonStr - A valid json formatted string.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface.
        TDFBuilder& setMetaDataAsJsonStr(const std::string& propertiesAsJsonStr);

    public: /// Optional
        /// Set the private key(In PEM format), which will be used by this SDK for encryption/decryption of the payload.
        /// \param privateKey - The PEM-encoded private key as a string.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, if the consumer of the SDK didn't provide one, the SDK
        /// will generate one. The default key size is 2048.
        TDFBuilder& setPrivateKey(const std::string& privateKey);

        /// Set the public key(In PEM format), which will be used by this SDK for encryption/decryption of the payload.
        /// \param publicKey - The PEM-encoded public key as a string.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, if the consumer of the SDK didn't provide one, the SDK
        /// will generate one. The default key size is 2048.
        TDFBuilder& setPublicKey(const std::string& publicKey);

        /// Sets the default size of each segment while performing encryption/decryption of the payload.
        /// \param segmentSize - The segment size in bytes.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, Default is set to 1024 * 1024 if one is not provided.
        TDFBuilder& setDefaultSegmentSize(unsigned int segmentSize);

        /// Set the encryption Object on the TDF instance.
        /// \param keyType - The key type which will be used for encryption/decryption of payload.
        /// \param cipherType - The cipher type
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, if the consumer of the SDK didn't provide one, the SDK
        /// will generate a default one, KeyType is 'split' and CipherType is 'Aes256GCM'.
        TDFBuilder& setEncryptionObject(KeyType keyType, CipherType cipherType);

        /// Sets the integrity algorithm and segment integrity algorithms onto a TDF instance.
        /// \param integrityAlgorithm - The type of algorithm used to create the root signature,
        /// found in the manifest integrityInformation.
        /// \param segmentIntegrityAlgorithm - The type of algorithm used to creat segment signatures.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, if the consumer of the SDK didn't provide one, the SDK
        /// will generate a default one, integrityAlgorithm is 'HS256' and same for 'segmentIntegrityAlgorithm'.
        TDFBuilder& setIntegrityAlgorithm(IntegrityAlgorithm integrityAlgorithm,
                                           IntegrityAlgorithm segmentIntegrityAlgorithm);

        /// Sets the key access type.
        /// \param keyAccessType - The key access type.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, if the consumer of the SDK didn't provide one, the SDK
        /// will use 'Remote'. If the keyAccessType is 'Wrapped'(offline mode), the user should
        /// also provide the KAS public key.
        TDFBuilder& setKeyAccessType(KeyAccessType keyAccessType);

        /// Set the key access object. TDF can have multiple key access object. However they all should have
        /// the same 'KeyAccessType'
        /// \param keyAccessObject - The key access object.
        /// \return - Return a reference of this instance.
        TDFBuilder& setKeyAccessObject(const KeyAccessObject& keyAccessObject);

        /// Set the protocol to be used for encryption and decryption.
        /// \param protocol - type of the protocol.
        /// \return - Return a reference of this instance.
        TDFBuilder& setProtocol(Protocol protocol);

        /// Set the secure reader url which will be used in html tdf.
        /// \param url - The secure reader url.
        /// \return - Return a reference of this instance.
        TDFBuilder& setSecureReaderURL(const std::string& url);

        /// Set the html template file path, sdk will look for these placeholders(<%= dataInput %>,
        /// <%= dataManifest %>, <%= url %>) and replace with tdf data.
        /// \param htmlTemplateFilePath - The html template file path.
        /// \return - Return a reference of this instance.
        TDFBuilder& setHtmlTemplateFilepath(const std::string& htmlTemplateFilePath);

        /// Set the html template data, sdk will look for these placeholders(<%= dataInput %>,
        /// <%= dataManifest %>, <%= url %>) and replace with tdf data.
        /// \param htmlTemplateData - The buffer, containing the template data.
        /// \return - Return a reference of this instance.
        TDFBuilder& setHtmlTemplateData(std::string htmlTemplateData);

        /// Set the MIME type of the tdf payload. If not set default mime type is
        /// assumed("application/octet-stream")
        /// \param mimeType - MIME type.
        /// \return - Return a reference of this instance.
        TDFBuilder& setPayloadMimeType(const std::string& mimeType);

    public: /// Optional - Logging
        /// Enable the logger to write logs to the console.
        /// \return - Return a reference of this instance.
        /// \param logLevel - The log level.
        /// NOTE: This is the optional interface.
        TDFBuilder&  enableConsoleLogging(LogLevel logLevel = LogLevel::Current);

        /// Set the external logger.
        /// NOTE: once this is set, the console will be disabled in case if it's enabled.
        /// \param externalLogger - The external logger shared ptr.
        /// \param logLevel - The log level.
        TDFBuilder&  setExternalLogger(std::shared_ptr<ILogger> externalLogger, LogLevel logLevel = LogLevel::Current);

    public: /// Optional - configure root CA's
        /// Set the cert authority which will be used in SSL handshake for all the network I/O.
        /// \param certAuthority - A string which holds the cert authority which will be used in SSL handshake
        ///                       for all the network I/O
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface. if the consumer of the SDK didn't provide one, the SDK
        /// will use the default ones packaged in library.
        TDFBuilder& setCertAuthority(const std::string& certAuthority);

        /// Set the cert authority which will be used in SSL handshake for all the network I/O.
        /// \param certAuthority - A string(R-value) which holds the cert authority which will be used in SSL handshake
        ///                       for all the network I/O
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface. if the consumer of the SDK didn't provide one, the SDK
        /// will use the default ones packaged in library.
        TDFBuilder& setCertAuthority(std::string&& certAuthority) noexcept;

        /// Destructor
        ~TDFBuilder();

        /// Remove default constructor
        TDFBuilder() = delete;

    protected:
        /// Validate the data set by the consumer of the TDFBuilder
        void validate();

        /// TODO this has no business being in the Builder, but the builder pattern
        /// is largely pointless versus TDFClient as it is just a bunch of duplicated
        /// setter funcs and a `validate()` call
        ///
        /// Return the network provider defined with `setHTTPServiceProvider`, or return a new
        /// default provider configured with
        /// \param defaultHeaders - a collection of HTTP headers to be used if no provider set
        std::shared_ptr<INetwork> getHTTPServiceProvider(HttpHeaders defaultHeaders) const;

        /// Set the callback interface which will invoked for all the http network operations.
        /// \param httpServiceProvider - A callback interface which the caller has to implement for performing the
        /// network http operations.
        /// \return - Unique ptr of the TDF3 instance.
        TDFBuilder& setHTTPServiceProvider(std::weak_ptr<INetwork> httpServiceProvider);


    private: /// Data
        friend TDF;
        friend TDFImpl;
        friend TDFClient;

        std::unique_ptr<TDFBuilderImpl> m_impl;
    };
}  // namespace virtru

#endif //VIRTRU_TDFBUILDER_H
