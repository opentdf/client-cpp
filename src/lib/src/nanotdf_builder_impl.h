/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/23
//

#ifndef VIRTRU_NANO_TDF_BUILDER_IMPL_H
#define VIRTRU_NANO_TDF_BUILDER_IMPL_H

#include <numeric>

#include "crypto/crypto_utils.h"
#include "nanotdf_builder.h"
#include "tdf_constants.h"
#include "policy_object.h"
#include "nanotdf//ecc_mode.h"
#include "nanotdf/symmetric_and_payload_config.h"
#include "nanotdf/policy_info.h"
#include "logger.h"
#include "entity_object.h"
#include "tdf_exception.h"
#include "sdk_constants.h"
#include "network_interface.h"
#include "utils.h"

namespace virtru {

    using namespace virtru;
    using namespace virtru::crypto;
    using namespace virtru::nanotdf;

   /// Forward declaration

    /// NOTE: This is an implementation detail and only NanoTDF and NanoTDF builder should have access to it.
    class NanoTDFBuilderImpl {
    public: // Interface

        /// Constructor
        /// \param user - The user of nano tdf in case of encryption, the user is the owner.
        explicit NanoTDFBuilderImpl(const std::string& user) : m_user{user} { }

        /// Return the state of the this object.
        /// \return - The string representing the state of this object.
        std::string toString() const {

            std::ostringstream os;
            auto hasKasPublicKey = !m_kasPublicKey.empty();
            auto dissems = m_policyObject.getDissems();

            os << '\n' << "NanoTDFBuilder information:" << '\n';

            os << "--- Http headers ---" << '\n';
            for (const auto& [key, value] :  m_httpHeaders) {
                if (Utils::iequals(key, kAuthorizationKey)) {
                    os << key <<  ":" << "***REDACT***" << '\n';
                } else {
                    os << key <<  ":" << value << '\n';
                }
            }

            os << "Eas url: " << m_easUrl<< '\n'
               << "Kas url: " << m_kasUrl << '\n'
               << "Offline mode: " <<  m_offlineMode << '\n'
               << "Kas public key: " << (hasKasPublicKey ? "available" : "need to fetch") << '\n'
               << "Curve name: " <<  ECCMode::GetEllipticCurveName (m_ellipticCurveType) << '\n'
               << "Cipher: " <<  SymmetricAndPayloadConfig::CipherTypeAsString(m_cipher) << '\n'
               << "Policy Type: " << PolicyInfo::PolicyTypeAsString(m_policyType) << '\n'
               << "Signature enable: " <<  (m_hasSignature ? "YES" : "NO") << '\n';

               if (m_hasSignature) {
                   os << "Signature curve name: " <<  ECCMode::GetEllipticCurveName (m_signatureECCMode) << '\n';
               }

            os << "Use ECDSABinding: " <<  (m_useECDSABinding ? "YES" : "NO") << '\n'
               << "Dissems: " << std::accumulate(dissems.begin(), dissems.end(), std::string(),
                                                 [](const std::string& a, const std::string& b) -> std::string {
                                                     return a + (a.length() > 0 ? "," : "") + b;
                                                 }) << '\n';
            os << "Ready to encrypt/decrypt..." << '\n';
            return os.str();
        }

    private: /// Data

        friend class NanoTDFBuilder;
        friend class NanoTDF;
        friend class NanoTDFImpl;
        friend class NanoTDFClient;
        friend class NanoTDFDatasetClient;

        std::string m_user;
        std::string m_easUrl;
        std::string m_kasUrl;
        std::string m_privateKey;
        std::string m_publicKey;
        std::string m_requestSignerPrivateKey;
        std::string m_requestSignerPublicKey;
        std::string m_kasPublicKey;
        std::string m_signerPrivateKey;
        std::string m_signerPublicKey;
        EllipticCurve m_signatureECCMode {EllipticCurve::SECP256R1};
        std::string m_rootCAs;
        std::vector<gsl::byte> m_compressedPubKey;
        PolicyObject m_policyObject;
        EntityObject m_entityObject;
        EllipticCurve m_ellipticCurveType {EllipticCurve::SECP256R1};
        NanoTDFPolicyType m_policyType {NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED};
        NanoTDFCipher m_cipher {NanoTDFCipher::AES_256_GCM_96_TAG};
        bool m_hasSignature {false};
        bool m_useECDSABinding {false};
        bool m_offlineMode {false};
        bool m_useOldNTDFFormat{false};
        HttpHeaders m_httpHeaders;
        std::weak_ptr<INetwork> m_networkServiceProvider;
        bool m_oidcMode = false; //TODO toggle this to true once we remove all other deprecated auth methods
    };
}

#endif //VIRTRU_NANO_TDF_BUILDER_IMPL_H
