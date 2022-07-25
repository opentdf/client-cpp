
/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/08/13
//


#ifndef TDF_SRC_NANOTDF_CLIENT_H
#define TDF_SRC_NANOTDF_CLIENT_H

#include "tdf_client_base.h"
#include "oidc_credentials.h"

namespace virtru {

    /// Forward declaration.
    class NanoTDFBuilder;
    class NanoTDF;
    class OIDCService;

    /// A nano tdf class to provide an simple interface for Python bindings. NOT intended for
    /// public API yet. This interface is subject to change.
    class NanoTDFClient: public TDFClientBase {
    public:
        /// Constructs a nano TDF client instance.
        /// NOTE: should me used for only offline decrypt operation.
        NanoTDFClient();

        /// Constructs a nano TDF client instance.
        /// \param easUrl - The eas URL.
        /// \param user - The registered user on EAS.
        NanoTDFClient(const std::string& easUrl, const std::string& user);

        /// Constructs a nano TDF client instance.
        /// \param easUrl - The eas URL.
        /// \param user - The registered user on EAS.
        /// \param clientKeyFileName -  Path to client key file.
        /// \param clientCertFileName - Path to client certificate file.
        /// \param sdkConsumerCertAuthority - Path to cert authority file.
        NanoTDFClient(const std::string& easUrl, const std::string& user, const std::string& clientKeyFileName,
                const std::string& clientCertFileName, const std::string& sdkConsumerCertAuthority);

        /// Constructor
        /// \param oidcCredentials - OIDC credentials
        /// \param kasUrl -  The KAS backend url
        NanoTDFClient(const OIDCCredentials& oidcCredentials, const std::string &kasUrl);

        /// Destroy the Client instance.
        ~NanoTDFClient();

        /// Copy constructor
        NanoTDFClient(const NanoTDFClient& client) = delete;

        /// Assignment operator
        NanoTDFClient& operator=(const NanoTDFClient& client)  = delete;

        /// Move copy constructor
        NanoTDFClient(NanoTDFClient&& client) = delete;

        /// Move assignment operator
        NanoTDFClient& operator=(NanoTDFClient&& client)  = delete;

    public: /// Encrypt and Decrypt
#ifndef SWIG
        /// Encrypt the data by reading from inputProvider and writing to outputProvider.
        /// \param inputProvider - InputProvider for reading the data.
        /// \param outputProvider -  OutputProvide for writing the TDF data.
        void encryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) override;

        /// Decrypt the tdf data by reading from inputProvider and writing to outputProvider.
        /// \param inputProvider - InputProvider for reading the TDF data.
        /// \param outputProvider -  OutputProvide for writing the decrypted data.
        void decryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) override;
#endif

        /// Encrypt the file to tdf format.
        /// \param tdfStorageType - The type of the tdf.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        void encryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) override;

        /// Encrypt the bytes to tdf format.
        /// \param tdfStorageType - The type of the tdf.
        /// \return std::vector<VBYTE> - The vector containing the encrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::vector<VBYTE> encryptData(const TDFStorageType &tdfStorageType) override;

        /// Decrypt file that are encrypted using old version of SDKs.
        /// \param inFilepath - The file on which the decryption is performed.
        /// \param outFilepath - The file path of the nano tdf after successful decryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        void decryptFileUsingOldFormat(const std::string& inFilepath, const std::string& outFilepath);

        /// Decrypt file to nano tdf file format.
        /// \param tdfStorageType - The type of the tdf.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        void decryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) override;

        /// Decrypt the bytes to nano tdf format.
        /// \param tdfStorageType - The type of the tdf.
        /// \return std::vector<VBYTE> - The vector containing the decrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::vector<VBYTE> decryptData(const TDFStorageType &tdfStorageType) override;

        /// Decrypt part of the data from tdf storage type.
        /// \param tdfStorageType - The type of the nano tdf.
        /// \param offset - The offset within the plaintext to return
        /// \param length - The length of the plaintext to return
        /// \return std::vector - The vector containing the decrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::vector<VBYTE> decryptDataPartial(const TDFStorageType &tdfStorageType, size_t offset, size_t length) override;

        /// Decrypt data from nano tdf format that are encrypted using old version of SDKs.
        /// \param encryptedData - The string containing a data to be decrypted.
        /// \return std::string - The string containing the plain data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string decryptStringUsingOldFormat(const std::string &plainData);

        /// Validate the TDF on decrypt(check if the TDF is singed by right entity). Throws exception
        /// on decrypt if the given public key doesn't match the one in TDF.
        /// \param signerPublicKey - The PEM-encoded public key as a string.
        void validateSignature(const std::string& signerPublicKey);

        /// Allow user to add data attribute
        /// \param dataAttribute - uri of the attribute
        /// \param kasUrl - kas url
        void addDataAttribute(const std::string &dataAttribute, const std::string &kasURL) override;

    public: /// Interface to save the state and later use when there is no network connectivity.
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

    public: // TDF validity check
        /// Check if the file is in valid NanoTDF format.
        /// \param filePath - The NanoTDF file.
        /// \return - Return true if it's valid NanoTDF format.
        static bool isValidNanoTDFFile(const std::string& filePath);

        /// Check if the data is in valid NanoTDF format.
        /// \param nanoTDFData - The NanoTDF data
        /// \return - Return true if it's valid NanoTDF format.
        static bool isValidNanoTDFData(const std::string& nanoTDFData);

        /// Set the callback interface which will invoked for all the http network operations.
        /// \param httpServiceProvider - A callback interface which the caller has to implement for performing the
        /// network http operations.
        void setHTTPServiceProvider(std::weak_ptr<INetwork> httpServiceProvider);

    private: /// Helpers
        /// Initialize the nano TDF builder which is used for creating the nano TDF
        /// instance used for encrypt and decrypt.
        /// \param newSDKKey - If true create a new sdk keypair.
        void initNanoTDFBuilder(bool newSDKKey = true);

        /// Fetch EntityObject
        void fetchEntityObject();

        /// Get vector of entity attribute objects
        /// \return Return vector of entity attribute objects
        std::vector<AttributeObject> getEntityAttrObjects() override;

        /// Get vector of subject attribute objects
        /// \return Return vector of subject attribute objects
        std::vector<AttributeObject> getSubjectAttrObjects() override;

    private: /// Data

        friend class NanoTDFDatasetClient;

        std::unique_ptr<NanoTDFBuilder> m_nanoTdfBuilder;
        std::unique_ptr<OIDCCredentials> m_oidcCredentials;
        std::unique_ptr<OIDCService> m_oidcService;
    };
}

#endif //VIRTRU_TDF_CLIENT_H
