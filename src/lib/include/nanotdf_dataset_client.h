/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/09/24
//


#ifndef TDF_SRC_NANOTDF_DATASET_CLIENT_H
#define TDF_SRC_NANOTDF_DATASET_CLIENT_H

#include "oidc_credentials.h"

namespace virtru {

    /// Forward declaration.
    class NanoTDFClient;
    class NanoTDF;

    class NanoTDFDatasetClient {
    public:
        /// Constructs a  NanoTDF dataset client instance.
        /// \param maxKeyIterations - Maximum number of encrypt operations before a new key is generated.
        /// NOTE: should me used for only offline decrypt operation.
        explicit NanoTDFDatasetClient(uint32_t maxKeyIterations = kNTDFMaxKeyIterations);

        /// Constructs a  NanoTDF dataset client instance.
        /// \param easUrl - The eas URL.
        /// \param user - The registered user on EAS.
        /// \param maxKeyIterations - Maximum number of encrypt operations before a new key is generated.
        NanoTDFDatasetClient(const std::string& easUrl, const std::string& user,
                uint32_t maxKeyIterations = kNTDFMaxKeyIterations);

        /// Constructs a  NanoTDF dataset client instance.
        /// \param easUrl - The eas URL.
        /// \param user - The registered user on EAS.
        /// \param clientKeyFileName -  Path to client key file.
        /// \param clientCertFileName - Path to client certificate file.
        /// \param sdkConsumerCertAuthority - Path to cert authority file.
        /// \param maxKeyIterations - Maximum number of encrypt operations before a new key is generated.
        NanoTDFDatasetClient(const std::string& easUrl, const std::string& user, const std::string& clientKeyFileName,
                      const std::string& clientCertFileName, const std::string& sdkConsumerCertAuthority,
                      uint32_t maxKeyIterations = kNTDFMaxKeyIterations);

        /// Constructs a NanoTDF dataset client instance.
        /// \param oidcCredentials - OIDC credentials
        /// \param kasUrl -  The KAS backend url
        /// \param maxKeyIterations - Maximum number of encrypt operations before a new key is generated.
        NanoTDFDatasetClient(const OIDCCredentials& oidcCredentials, const std::string &kasUrl,
                      uint32_t maxKeyIterations = kNTDFMaxKeyIterations);

        /// Destroy the Client instance.
        ~NanoTDFDatasetClient();

        /// Copy constructor
        NanoTDFDatasetClient(const NanoTDFDatasetClient& client) = delete;

        /// Assignment operator
        NanoTDFDatasetClient& operator=(const NanoTDFDatasetClient& client)  = delete;

        /// Move copy constructor
        NanoTDFDatasetClient(NanoTDFDatasetClient&& client) = delete;

        /// Move assignment operator
        NanoTDFDatasetClient& operator=(NanoTDFDatasetClient&& client)  = delete;

    public: /// Encrypt and Decrypt
        /// Encrypt the file to nano tdf format.
        /// \param inFilepath - The file on which the encryption is performed.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        void encryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Encrypt the data to nano tdf format.
        /// \param plainData - The string containing the data to be encrypted.
        /// \return std::string_view - The string_view(a reference to encrypted data).
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view encryptString(const std::string &plainData);

        /// Decrypt file.
        /// \param inFilepath - The file on which the decryption is performed.
        /// \param outFilepath - The file path of the nano tdf after successful decryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        void decryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Decrypt data from nano tdf format.
        /// \param encryptedData - The string containing a data to be decrypted.
        /// \return std::string_view - The string_view(a reference to plain data).
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view decryptString(const std::string& encryptedData);

        /// Validate the TDF on decrypt(check if the TDF is singed by right entity). Throws exception
        /// on decrypt if the given public key doesn't match the one in TDF.
        /// \param signerPublicKey - The PEM-encoded public key as a string.
        void validateSignature(const std::string& signerPublicKey);

    public: /// Interface
        /// Enable the internal logger class to write logs to the console for given LogLevel.
        /// The default Loglevel is to keep the current level if not specified.
        /// \param logLevel - The log level
        void enableConsoleLogging(LogLevel logLevel = LogLevel::Current);

    public: /// Policy interface(users, Attributes)
        /// Add access to the TDF file/data for the users in the list
        /// \param users - Share the TDF with the users in the vector
        void shareWithUsers(const std::vector<std::string>& users);

        /// Allow user to read entity attributes
        /// \return Return vector of entityAttributes -- unique resource locater of each attribute
        //          associated with the EntityObject for this client instance
        std::vector<std::string> getEntityAttributes();

        /// Allow user to add data attributes
        /// \param displayName - Can be empty string
        /// \param kasPublicKey - Can be empty string
        /// \param kasUrl - Can be empty string
        void addDataAttribute(const std::string& dataAttribute, const std::string& kasUrl);

        ///Allow user to read data attributes associated with this instances of client (to be replaced by inspectDataAttributes)
        /// \return Return vector of dataAttributes -- unique resource locater of each data attribute
        //          associated with this client instance
        std::vector<std::string> getDataAttributes();

    public: /// Interface
        /// Set the entity private key(In PEM format), which will be used by this SDK for encryption/decryption of
        /// the payload/policy. The private key should be from one of predefined curves defined in tdf_constants.h
        /// \param privateKey - The PEM-encoded private key as a string.
        /// \param curve - The elliptic curve of the key-pair
        /// NOTE: This is the optional interface, if the consumer of the SDK didn't provide one, the SDK
        /// will generate one.
        void setEntityPrivateKey(const std::string& entityPrivateKey, EllipticCurve curve);

        /// Set the signer private key(In PEM format). Calling this method enables the signature entry in nano tdf
        /// The ECC private key should be from one of predefined curves which are defined in tdf_constants.h.
        /// \param signerPrivateKey - The PEM-encoded signer private key.
        /// \param curve - The elliptic curve of the public key
        /// \return - Return a reference of this instance.
        /// NOTE: This is the optional interface, signature is not enabled by default.
        void setSignerPrivateKey(const std::string& signerPrivateKey, EllipticCurve curve);

        /// Set the kas decrypter public-key(In PEM format). This can be used for offline mode.
        /// \param decrypterPublicKey - The PEM-encoded public key as a string.
        /// NOTE: This interface make sense only if the SDK perform decryption in offline mode and the SDK knows
        /// the public key used for encrypting the tdf.
        void setDecrypterPublicKey(const std::string& decrypterPublicKey);

        /// Return the entity private key in PEM format and the curve of the key.
        /// \return - The entity private key in PEM format and the curve of the key.
        std::pair<std::string, std::string> getEntityPrivateKeyAndCurve() const;

    private:
        // Initialize the NanoTDF
        void initializeNanoTDF();

    private: /// Data
        bool m_offline{false};
        std::uint32_t m_MaxKeyIterations;
        std::unique_ptr<NanoTDFClient> m_nanoTdfClient;
        std::unique_ptr<NanoTDF> m_nanoTdf;
    };

}

#endif //TDF_SRC_NANOTDF_DATASET_CLIENT_H
