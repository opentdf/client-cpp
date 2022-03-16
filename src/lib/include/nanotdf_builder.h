/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/02
//

#ifndef VIRTRU_NANO_TDF_BUILDER_H
#define VIRTRU_NANO_TDF_BUILDER_H

#include <memory>
#include <string>
#include <unordered_map>

#include "tdf_constants.h"
#include "network_interface.h"

namespace virtru {

    using namespace virtru;

    ///
    /// NOTE: User of this SDK has to catch virtru::exception. This sdk throws exception if any of the interfaces are
    /// not used or not configured correctly.
    ///

    /// Forward declaration.
    class PolicyObject;
    class EntityObject;
    class NanoTDF;
    class NanoTDFImpl;
    class NanoTDFBuilderImpl;
    class ILogger;
    class INetwork;
    class NanoTDFDatasetClient;

    class NanoTDFBuilder {
    public: /// NOTE: This is a required interface. There are no default implementations,
        /// the consumer of the SDK must provide these

        /// Constructor
        /// \param user - The owner of this TDF creation process
        explicit NanoTDFBuilder(const std::string& user);

        /// Set the eas url that will be used for nano tdf operations.
        /// \param easUrl - The eas(Entity Attribute Server) url.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& setEasUrl(const std::string& easUrl);

        /// Return a unique ptr to the NanoTDF object. This can be used to exercise operations like
        /// encryption/decryption of the payload.
        /// \return - Unique ptr of the NanoTDF instance.
        /// NOTE: Throws an virtru::exception if any of the information is missing for construction
        /// of the NanoTDF object.
        std::unique_ptr<NanoTDF> build();

        /// Return a unique ptr of Dataset of NanoTDF object. This can be use to exercise operation like
        /// encryption/decryption of the payload.
        /// \param maxKeyIterations - Maximum number of encrypt operations before a new key is generated.
        /// \return - Unique ptr of the NanoTDF instance.
        /// NOTE: Throws an virtru::exception if any of the information is missing for construction of the TDF object.
        std::unique_ptr<NanoTDF> buildNanoTDFDataset(uint32_t maxKeyIterations);

    public: /// Optional
        /// Set the entity object. This can be used for offline mode.
        /// \param entityObject - The key access type.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& setEntityObject(const EntityObject& entityObject);

        /// Set the policy object on the TDF instance.
        /// \param policyObject - The policy object.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& setPolicyObject(const PolicyObject& policyObject);

        /// Set the Elliptic-curve to be used for encryption/decryption of the payload/policy.
        /// \param curve - The elliptic curve. The default curve is "secp256k1"
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& setEllipticCurve(EllipticCurve curve);

        /// Set the entity private key(In PEM format), which will be used by this SDK for encryption/decryption of
        /// the payload/policy. The private key should be from one of predefined curves defined in tdf_constants.h
        /// \param privateKey - The PEM-encoded private key as a string.
        /// \param curve - The elliptic curve of the key-pair
        /// NOTE: This is the optional interface, if the consumer of the SDK didn't provide one, the SDK
        /// will generate one.
        NanoTDFBuilder& setEntityPrivateKey(const std::string& privateKey, EllipticCurve curve);

        /// Set the signer private key(In PEM format). Calling this method enables the signature entry in nano tdf
        /// The ECC private key should be from one of predefined curves which are defined in tdf_constants.h.
        /// \param signerPrivateKey - The PEM-encoded signer private key.
        /// \param curve - The elliptic curve of the public key
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, signature is not enabled by default.
        NanoTDFBuilder& setSignerPrivateKey(const std::string& signerPrivateKey, EllipticCurve curve);

        /// Validate the TDF on decrypt(check if the TDF is singed by right entity). Throws exception
        /// on decrypt if the given public key doesn't match the one in TDF.
        /// \param signerPublicKey - The PEM-encoded public key as a string.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& validateSignature(const std::string& signerPublicKey);

        /// Set the kas url that will be used for tdf operations. This can be used for offline mode, in online case
        /// this information is Entity Object.
        /// \param kasUrl - The kas(Key Access Server) url.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& setKasUrl(const std::string& kasUrl);

        /// Feature flag for OIDC-based auth flows
        /// In this mode, EOs are not used and EAS is not called
        /// Additionally, KAS requests will be different.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& enableOIDC(bool enableOIDC);

        /// Set the kas public key(In PEM format). This can be used for offline mode.
        /// \param publicKey - The PEM-encoded kas public key as a string.
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, kas public is part of Entity object.
        NanoTDFBuilder& setKasPublicKey(const std::string& kasPublicKey);

        /// Set the offline mode.
        /// \param state - If true, all the nano tdf operation are performed without a network connection.
        /// NOTE: All the necessary keys needs to set to perform offline nano tdf operations.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& setOffline(bool state);

        /// Set the policy type of the tdf. The default is embedded policy as plain text.
        /// \param policyType - The policy type
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, the default is EMBEDDED_POLICY_ENCRYPTED
        NanoTDFBuilder& setPolicyType(NanoTDFPolicyType policyType);

        /// Set the symmetric ciphers to use for encrypting the payload and/or
        /// the policy (if the policy is encrypted). The default is aes-256 with gcm 64bit tag.
        /// \param cipher - The symmetric cipher
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& setCipher(NanoTDFCipher cipher);

        /// Enable ecdsa policy binding, the default is gmac.
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& enableECDSABinding();

        /// Disable ecdsa policy binding
        /// \return - Return a reference of this instance.
        NanoTDFBuilder& disableECDSABinding();

        /// Get current ecdsa policy binding setting
        /// \return - true if enabled, false otherwise
        bool getECDSABinding();

        /// Enable the flag to use old format(smaller IV) for decrypting the
        // Nano tdfs
        void enableFlagToUseOldFormatNTDF();

        /// Disable the flag to use old format(smaller IV) for decrypting the
        // Nano tdfs
        void disableFlagToUseOldFormatNTDF();

    public: /// Optional - Logging
        /// Enable the logger to write logs to the console.
        /// \return - Return a reference of this instance.
        /// \param logLevel - The log level.
        /// NOTE: This is the optional interface.
        NanoTDFBuilder&  enableConsoleLogging(LogLevel logLevel = LogLevel::Current);

        /// Set the external logger.
        /// NOTE: Setting this will disable the console output if it was enabled
        /// \param externalLogger - The external logger shared ptr.
        /// \param logLevel - The log level.
        NanoTDFBuilder&  setExternalLogger(std::shared_ptr<ILogger> externalLogger, LogLevel logLevel = LogLevel::Current);

    public: /// Network I/O

        /// Set the http headers will be used for all the all the http network operations.
        /// \param properties - A unordered map holding the http headers.
        /// \return - Unique ptr of the TDF instance.
        NanoTDFBuilder& setHttpHeaders(const std::unordered_map<std::string, std::string>& headers);

    public: /// Optional - configure root CA's
        /// Set the certAuthority which will be used in SSL handshake for all the network I/O.
        /// \param certAutority - A string which holds the cert authority which will be used in SSL handshake
        ///                       for all the network I/O
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface. if the consumer of the SDK didn't provide one, the SDK
        /// will use the default ones packaged in library.
        NanoTDFBuilder& setCertAuthority(const std::string& certAutority);

        /// Set the cert authority which will be used in SSL handshake for all the network I/O.
        /// \param certAutority - A string(R-value) which holds the cert authority which will be used in SSL handshake
        ///                       for all the network I/O
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface. if the consumer of the SDK didn't provide one, the SDK
        /// will use the default ones packaged in library.
        NanoTDFBuilder& setCertAuthority(std::string&& certAutority) noexcept;

        /// Destructor
        ~NanoTDFBuilder();

        /// Remove default constructor
        NanoTDFBuilder() = delete;

    protected:
        /// Validate the data set by the consumer of the NanoTDFBuilder
        void validate();

        /// TODO this has no business being in the Builder, but the builder pattern
        /// is largely pointless versus TDFClient as it is just a bunch of duplicated
        /// setter funcs and a `validate()` call
        ///
        /// Return the network provider defined with `setHTTPServiceProvider`, or return a new
        /// default provider configured with
        /// \param defaultHeaders - a collection of HTTP headers to be used if no provider set
        std::shared_ptr<INetwork> getHTTPServiceProvider(HttpHeaders defaultHeaders) const;

    private: /// Data
        friend class NanoTDF;
        friend class NanoTDFImpl;
        friend class NanoTDFClient;
        friend class NanoTDFDatasetClient;

        std::unique_ptr<NanoTDFBuilderImpl> m_impl;
    };
}

#endif //VIRTRU_NANO_TDF_BUILDER_H
