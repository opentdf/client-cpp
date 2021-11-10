//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/02
//  Copyright 2020 Virtru Corporation
//

#include <fstream>
#include "nlohmann/json.hpp"

#include "tdf_logging_interface.h"
#include "nanotdf_builder_impl.h"
#include "attribute_objects_cache.h"
#include "crypto/ec_key_pair.h"
#include "nanotdf/ecc_mode.h"
#include "nanotdf.h"
#include "nanotdf_builder.h"

namespace virtru {

    using namespace virtru;
    using namespace virtru::nanotdf;

    /// Constructor
    NanoTDFBuilder::NanoTDFBuilder(const std::string& user)
            : m_impl(std::make_unique<NanoTDFBuilderImpl>(user)) {
    }

    /// Set the eas url that will be used for nano tdf operations.
    /// \param easUrl - The eas(Entity Attribute Server) url.
    /// \return - Return a reference of this instance.
    NanoTDFBuilder& NanoTDFBuilder::setEasUrl(const std::string& easUrl) {

        m_impl->m_easUrl = easUrl;

        return *this;
    }

    /// Set the http headers will be used for all the all the http network operations.
    NanoTDFBuilder& NanoTDFBuilder::setHttpHeaders(const std::unordered_map<std::string, std::string>& headers) {

        m_impl->m_httpHeaders = headers;

        return *this;
    }

    /// Return a unique ptr of NanoTDF object. This can be use to exercise operation like
    /// encryption/decryption of the payload.
    std::unique_ptr<NanoTDF> NanoTDFBuilder::build() {

        // validate the data before constructing TDF instance.
        validate();

        LogInfo(m_impl->toString());

        return std::unique_ptr<NanoTDF>(new NanoTDF(*this, false, kNTDFMaxKeyIterations));
    }

    /// Return a unique ptr of Dataset of NanoTDF object. This can be use to exercise operation like
    /// encryption/decryption of the payload.
    std::unique_ptr<NanoTDF> NanoTDFBuilder::buildNanoTDFDataset(uint32_t maxKeyIterations) {
        // validate the data before constructing TDF instance.
        validate();

        LogInfo(m_impl->toString());

        return std::unique_ptr<NanoTDF>(new NanoTDF(*this, true, maxKeyIterations));
    }

    /// Set the entity object. This can be used for offline mode.
    NanoTDFBuilder& NanoTDFBuilder::setEntityObject(const EntityObject& entityObject) {

        m_impl->m_entityObject = entityObject;

        return *this;
    }

    /// Set the policy object on the TDF instance.
    NanoTDFBuilder& NanoTDFBuilder::setPolicyObject(const PolicyObject& policyObject) {

        m_impl->m_policyObject = policyObject;

        return *this;
    }

    /// Set the Elliptic-curve to be used for encryption/decryption of the payload/policy.
    NanoTDFBuilder& NanoTDFBuilder::setEllipticCurve(EllipticCurve curve) {

        m_impl->m_ellipticCurveType = curve;

        return *this;
    }

    /// Set the entity private key(In PEM format), which will be used by this SDK for encryption/decryption of
    /// the payload/policy. The private key should be from one of predefined curves defined in tdf_constants.h
    NanoTDFBuilder& NanoTDFBuilder::setEntityPrivateKey(const std::string& privateKey, EllipticCurve curve) {

        m_impl->m_ellipticCurveType = curve;
        m_impl->m_privateKey = privateKey;

        auto curveName = ECCMode::GetEllipticCurveName(curve);
        m_impl->m_publicKey =  ECKeyPair::GetPEMPublicKeyFromPrivateKey(privateKey, curveName);

        return *this;
    }


    /// Set the signer private key(In PEM format). Calling this method enables the signature entry in nano tdf
    /// The ECC private key should be from one of predefined curves which are defined in tdf_constants.h.
    NanoTDFBuilder& NanoTDFBuilder::setSignerPrivateKey(const std::string& signerPrivateKey, EllipticCurve curve){
        m_impl->m_signerPrivateKey = signerPrivateKey;
        m_impl->m_signatureECCMode = curve;
        m_impl->m_hasSignature = true;

        return *this;
    }

    /// Validate the TDF on decrypt(check if the TDF is singed by right entity). Throws exception
    /// on decrypt if the given public key doesn't match the one in TDF.
    NanoTDFBuilder& NanoTDFBuilder::validateSignature(const std::string& signerPublicKey) {

        m_impl->m_signerPublicKey = signerPublicKey;

        return *this;
    }


    /// Set the kas url that will be used for tdf operations. This can be used for offline mode, in online case
    NanoTDFBuilder& NanoTDFBuilder::setKasUrl(const std::string& kasUrl) {

        m_impl->m_kasUrl = kasUrl;

        return *this;
    }

    /// Enable OIDC mode
    NanoTDFBuilder &NanoTDFBuilder::enableOIDC(bool enableOIDC) {

        m_impl->m_oidcMode = enableOIDC;

        return *this;
    }


    /// Set the kas public key(In PEM format). This can be used for offline mode.
    NanoTDFBuilder& NanoTDFBuilder::setKasPublicKey(const std::string& kasPublicKey) {

        m_impl->m_kasPublicKey = kasPublicKey;

        return *this;
    }

    /// Set the offline mode.
    NanoTDFBuilder& NanoTDFBuilder::setOffline(bool state) {

        m_impl->m_offlineMode = state;

        return *this;
    }

    /// TODO: - The default should be embedded policy as encrypted text.
    /// Set the policy type of the tdf. The default is embedded policy as plain text.
    NanoTDFBuilder& NanoTDFBuilder::setPolicyType(NanoTDFPolicyType policyType) {

        m_impl->m_policyType = policyType;

        return *this;
    }

    /// Set the symmetric ciphers to use for encrypting the payload and/or
    /// the policy (if the policy is encrypted). The default is aes-256 with gcm 64bit tag.
    NanoTDFBuilder& NanoTDFBuilder::setCipher(NanoTDFCipher cipher) {

        m_impl->m_cipher = cipher;

        return *this;
    }

    /// Enable ecdsa policy binding, the default is gmac.
    NanoTDFBuilder& NanoTDFBuilder::enableECDSABinding() {

        m_impl->m_useECDSABinding = true;

        return *this;
    }

    /// Disable ecdsa policy binding
    NanoTDFBuilder& NanoTDFBuilder::disableECDSABinding() {

        m_impl->m_useECDSABinding = false;

        return *this;
    }

    /// Return state of ecdsa policy binding setting
    bool NanoTDFBuilder::getECDSABinding() {

        return m_impl->m_useECDSABinding;
    }

    /// Disable the flag to use old format(smaller IV) for decrypting the
    // Nano tdfs
    void NanoTDFBuilder::enableFlagToUseOldFormatNTDF() {
        m_impl->m_useOldNTDFFormat = true;
    }

    /// Disable the flag to use old format(smaller IV) for decrypting the
    // Nano tdfs
    void NanoTDFBuilder::disableFlagToUseOldFormatNTDF() {
        m_impl->m_useOldNTDFFormat = false;
    }

    /// Enable the logger to write logs to the console.
    NanoTDFBuilder&  NanoTDFBuilder::enableConsoleLogging(LogLevel logLevel) {

        Logger::getInstance().setLogLevel(logLevel);
        Logger::getInstance().enableConsoleLogging();

        return *this;
    }

    /// Set the external logger.
    NanoTDFBuilder&  NanoTDFBuilder::setExternalLogger(std::shared_ptr<ILogger> externalLogger, LogLevel logLevel) {

        Logger::getInstance().setLogLevel(logLevel);
        Logger::getInstance().setExternalLogger(std::move(externalLogger));

        return *this;
    }

    /// Destructor
    NanoTDFBuilder::~NanoTDFBuilder() = default;

    /// Validate the data set by the consumer of the TDFBuilder
    void NanoTDFBuilder::validate() {

        ///
        /// Set the EC key pair if they are not set.
        ///
        auto privateKeyIsSet = !m_impl->m_privateKey.empty();
        auto pubicKeyIsSet = !m_impl->m_publicKey.empty();

        if (privateKeyIsSet != pubicKeyIsSet) {
            ThrowException("Both private and public key must be set.");
        } else if(!pubicKeyIsSet && !privateKeyIsSet) {

            auto curveName = ECCMode::GetEllipticCurveName(m_impl->m_ellipticCurveType);
            auto sdkECKeyPair = ECKeyPair::Generate(curveName);
            m_impl->m_privateKey = sdkECKeyPair->PrivateKeyInPEMFormat();
            m_impl->m_publicKey = sdkECKeyPair->PublicKeyInPEMFormat();
        }

        m_impl->m_compressedPubKey = ECKeyPair::CompressedECPublicKey( m_impl->m_publicKey);

        if (m_impl->m_offlineMode) {
            LogInfo("SDK is configured for offline mode.");
        } else {
            // When using OIDC mode, EO and EAS are not set and should not be assumed.
            if (m_impl->m_oidcMode) {
                if (m_impl->m_kasUrl.empty()) {
                    ThrowException("KAS URL must be set in OIDC mode");
                }
                if (m_impl->m_kasPublicKey.empty()) {
                    auto kasKeyUrl = m_impl->m_kasUrl + kKasPubKeyPath + "?algorithm=ec:secp256r1";
                    auto kasPublicKey = Utils::getKasPubkeyFromURL(kasKeyUrl);
                    LogTrace("KAS public key was set, fetched from provided KAS URL: " + kasPublicKey);
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

                // If entity object is set get the kas url and public key(if not set by user).
                if (!m_impl->m_entityObject.getUserId().empty()) {
                    AttributeObjectsCache attributeObjectsCache {m_impl->m_entityObject};

                    if (!attributeObjectsCache.hasDefaultAttribute()) {
                        ThrowException("Default attribute missing from the entity object.");
                    }

                    auto attributeObject = attributeObjectsCache.getDefaultAttributeObject();

                    m_impl->m_kasUrl = attributeObject.getKasBaseUrl();

                    // If the kas public key is missing, get it from the entity object.
                    if (m_impl->m_kasPublicKey.empty()) {
                        m_impl->m_kasPublicKey = attributeObject.getKasPublicKey();
                    }
                }

                if (m_impl->m_entityObject.getUserId().empty()) {
                    ThrowException("Entity object is missing.");
                }
            }
        }
    }
}
