/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/28.
//

#ifndef VIRTRU_BUILDER_IMPL_H
#define VIRTRU_BUILDER_IMPL_H

#include "tdf_constants.h"
#include "policy_object.h"
#include "logger.h"
#include "key_access_object.h"
#include "entity_object.h"
#include "tdf_exception.h"
#include "crypto/rsa_key_pair.h"
#include "tdf.h"
#include "network_interface.h"
#include "sdk_constants.h"
#include "crypto/crypto_utils.h"

#include <boost/algorithm/string.hpp>
#include <numeric>

namespace virtru {

    /// Forward declaration
    class TDFImpl;
    class TDFClient;

    /// NOTE: This is an implementation detail and only TDF and TDF builder should have access to it.
    class TDFBuilderImpl {
    public: // Interface

        /// Constructor
        /// \param user - The user of tdf in case of encryption, the user is the owner.
        /// \param easUrl - The eas url.
        explicit TDFBuilderImpl(const std::string& user) : m_user{user} {

        }

        /// Return the state of the this object.
        /// \return - The string representing the state of this object.
        std::string toString() {

            std::ostringstream os;
            auto hasKasPublicKey = !m_kasPublicKey.empty();
            auto dissems = m_policyObject.getDissems();

            os << '\n' << "TDFBuilder information:" << '\n'
               << '\n' << "--- Key access objects ---" << '\n';

            for (const auto& obj: m_keyAccessObjects) {
                os << "KeyAccessType: " <<  obj.getKeyAccessTypeAsStr() << '\n'
                   << "Kas url: " << obj.getKasUrl() << '\n';
            }

            os << "--- Http headers ---" << '\n';
            for (const auto& [key, value] :  m_httpHeaders) {
                if (boost::iequals(key, kAuthorizationKey)) {
                    os << key <<  ":" << "***REDACT***" << '\n';
                } else {
                    os << key <<  ":" << value << '\n';
                }
            }

            os << "Eas url: " << m_easUrl<< '\n'
               << "Kas public key: " << (hasKasPublicKey ? "available" : "need to fetch") << '\n'
			   << "OIDC mode enabled: " << m_oidcMode << '\n'
               << "Key type: " <<  ((KeyType::split == m_keyType) ? "split" : "Unknown") << '\n'
               << "Cipher: " <<  ((CipherType::Aes256GCM == m_cipherType) ? "Aes256GCM" : "Aes265CBC") << '\n'
               << "Key access object is set..." << '\n'
               << "Dissems: " << std::accumulate(dissems.begin(), dissems.end(), std::string(),
                                                 [](const std::string& a, const std::string& b) -> std::string {
                                                     return a + (a.length() > 0 ? "," : "") + b;
                                                 }) << '\n'
               << "Default segment size: " << m_segmentSize << '\n'
               << "Integrity algorithm: " << ((m_integrityAlgorithm == IntegrityAlgorithm::HS256) ? "HS256" : "GMAC") << '\n'
               << "Segment integrity algorithm: " << ((m_segmentIntegrityAlgorithm == IntegrityAlgorithm::HS256) ? "HS256" : "GMAC") << '\n'
               << "Payload MIME Type: " << m_mimeType << '\n'
               << "Meta data: " << m_metadataAsJsonStr << '\n';

            os << "Protocol:" << ((m_protocol == Protocol::Html) ? " html" : " zip") << '\n';
            if (m_protocol == Protocol::Html) {
                os << "Secure reader url: " << m_secureReaderUrl<< '\n';
            }

            os << "Ready to encrypt/decrypt..." << '\n';
            return os.str();
        }

        /// Destructor
        ~TDFBuilderImpl() = default;

    private:
        friend TDFBuilder;
        friend TDF;
        friend TDFImpl;
        friend TDFClient;

        std::string m_user;
        std::string m_easUrl;
        std::string m_kasUrl;
        std::string m_privateKey;
        std::string m_publicKey;
        std::string m_requestSignerPrivateKey;
        std::string m_requestSignerPublicKey;
        std::string m_kasPublicKey;
        std::string m_metadataAsJsonStr;
        std::string m_rootCAs;
        std::string m_secureReaderUrl;
        std::string m_mimeType{kDefaultMimeType};
        std::string m_kekBase64;
        unsigned int m_segmentSize {1024 * 1024};
        PolicyObject m_policyObject;
        std::vector<KeyAccessObject> m_keyAccessObjects;
        std::vector<std::string> m_htmlTemplateTokens;
        std::vector<Assertion> m_assertions;
        EntityObject m_entityObject;
        KeyType m_keyType {KeyType::split};
        KeyAccessType m_keyAccessType {KeyAccessType::Remote};
        CipherType m_cipherType {CipherType::Aes256GCM};
        IntegrityAlgorithm m_integrityAlgorithm {IntegrityAlgorithm::HS256};
        IntegrityAlgorithm m_segmentIntegrityAlgorithm {IntegrityAlgorithm::GMAC};
        Protocol m_protocol{Protocol::Zip};
        HttpHeaders m_httpHeaders;
        std::weak_ptr<INetwork> m_networkServiceProvider;
        bool m_oidcMode{false}; //TODO toggle this to true once we remove all other deprecated auth methods
        bool m_overridePayloadKey{false};
        WrappedKey m_payloadKey;
        bool m_overrideWrappedKey{false};
        WrappedKey m_wrappedKey = symmetricKey<kKeyLength>();
    };
}  // namespace virtru

#endif //VIRTRU_BUILDER_IMPL_H
