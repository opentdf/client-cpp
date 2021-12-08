//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/04/24
//  Copyright 2020 Virtru Corporation
//

#ifndef VIRTRU_TDF_CLIENT_H
#define VIRTRU_TDF_CLIENT_H

#include "attribute_object.h"
#include "entity_object.h"
#include "policy_object.h"
#include "tdf_client_base.h"
#include "oidc_credentials.h"
#include <tdf_constants.h>
#include <unordered_set>

#include <memory>
#include <set>

namespace virtru {

    /// Forward declaration.
    class TDFBuilder;
    class TDF;
    class OIDCService;

    /// A helper class to provide an simple interface for Python bindings. NOT intended for
    /// public API yet. This interface is subject to change.
    class TDFClient : public TDFClientBase {
      public:
        /// DEPRECATED - use OIDC constructors
        /// Constructs a TDF client instance.
        /// \param easUrl - The eas URL.
        /// \param user - The username/email of the user encrypting data.
        TDFClient(const std::string &easUrl, const std::string &user);

        /// Constructs a TDF client instance.
        /// \param backendUrl - The eas URL.
        /// \param user - The registered user on EAS.
        /// \param clientKeyFileName -  Path to client key file.
        /// \param clientCertFileName - Path to client certificate file.
        /// \param sdkConsumerCertAuthority - Path to cert authority file.
        TDFClient(const std::string &backendUrl, const std::string &user, const std::string &clientKeyFileName,
                   const std::string &clientCertFileName, const std::string &sdkConsumerCertAuthority);

        /// Constructor
        /// \param oidcCredentials - OIDC credentials
        /// \param kasUrl -  The KAS backend url
        TDFClient(const OIDCCredentials& oidcCredentials, const std::string &kasUrl);

        /// Default constructor is not supported
        TDFClient() = delete;

        /// Destroy the Client instance.
        ~TDFClient() override;

        /// Copy constructor
        TDFClient(const TDFClient &client) = delete;

        /// Assignment operator
        TDFClient &operator=(const TDFClient &client) = delete;

        /// Move copy constructor
        TDFClient(TDFClient &&client) = delete;

        /// Move assignment operator
        TDFClient &operator=(TDFClient &&client) = delete;

      public: /// Encrypt and Decrypt
        /// Encrypt the file to tdf format.
        /// \param inFilepath - The file on which the encryption is performed.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        void encryptFile(const std::string &inFilepath, const std::string &outFilepath) override;

#ifndef SWIG
        /// Encrypt the data to tdf format.
        /// \param plainData - The string containing the data to be encrypted.
        /// \return std::string - The string containing the encrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string encryptString(const std::string &plainData) override;
#endif

        /// Encrypt the bytes to tdf format.
        /// \param plainData - The vector containing the bytes to be encrypted.
        /// \return std::vector<VBYTE> - The vector containing the encrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::vector<VBYTE> encryptData(const std::vector<VBYTE> &plainData) override;

        /// Decrypt file.
        /// \param inFilepath - The file on which the decryption is performed.
        /// \param outFilepath - The file path of the tdf after successful decryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        void decryptFile(const std::string &inFilepath, const std::string &outFilepath) override;

#ifndef SWIG
        /// Decrypt data from tdf format.
        /// \param encryptedData - The string containing a data to be decrypted.
        /// \return std::string - The string containing the plain data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string decryptString(const std::string &encryptedData) override;
#endif

        /// Decrypt the bytes from tdf format.
        /// \param encryptedData - The vector containing the bytes to be decrypted.
        /// \return std::vector - The vector containing the plain data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::vector<VBYTE> decryptData(const std::vector<VBYTE> &encryptedData) override;

      private: /// Helpers
        /// Initialize the TDF builder which is used for creating the TDF instance
        /// used for encrypt and decrypt.
        void initTDFBuilder();

        /// DEPRECATED - OIDC doesn't use entity objects
        /// Get vector of entity attribute objects
        /// \return Return vector of entity attribute objects
        std::vector<AttributeObject> getEntityAttrObjects() override;

        /// Get vector of subject attribute objects
        /// \return Return vector of subject attribute objects
        std::vector<AttributeObject> getSubjectAttrObjects() override;

      private: /// Data
        std::unique_ptr<TDFBuilder> m_tdfBuilder;
        std::unique_ptr<OIDCCredentials> m_oidcCredentials;
        std::unique_ptr<OIDCService> m_oidcService;
    };
} // namespace virtru

#endif //VIRTRU_TDF_CLIENT_H
