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

#ifndef VIRTRU_TDF_CLIENT_BASE_H
#define VIRTRU_TDF_CLIENT_BASE_H

#include "attribute_object.h"
#include "entity_object.h"
#include "policy_object.h"
#include "network_interface.h"
#include "tdf_storage_type.h"
#include <tdf_constants.h>
#include <unordered_set>
#include <memory>
#include <set>

namespace virtru {

    // Forward declaration
    class IInputProvider;
    class IOutputProvider;

    /// A helper base class to provide an simple interface for Python bindings. NOT intended for
    /// public API yet. This interface is subject to change.
    class TDFClientBase {
      public:
        /// Constructs a TDF client instance.
        /// \param easUrl - The eas URL.
        /// \param user - The registered user on EAS.
        TDFClientBase(const std::string &easUrl, const std::string &user);

        /// Constructs a TDF client instance.
        /// \param easUrl - The eas URL.
        /// \param user - The registered user on EAS.
        /// \param clientKeyFileName -  Path to client key file.
        /// \param clientCertFileName - Path to client certificate file.
        /// \param sdkConsumerCertAuthority - Path to cert authority file.
        TDFClientBase(const std::string &easUrl, const std::string &user, const std::string &clientKeyFileName,
                  const std::string &clientCertFileName, const std::string &sdkConsumerCertAuthority);

        /// Default constructor is not supported
        TDFClientBase() = delete;

        /// Destroy the Client instance.
        virtual ~TDFClientBase();

        /// Copy constructor
        TDFClientBase(const TDFClientBase &client) = delete;

        /// Assignment operator
        TDFClientBase &operator=(const TDFClientBase &client) = delete;

        /// Move copy constructor
        TDFClientBase(TDFClientBase &&client) = delete;

        /// Move assignment operator
        TDFClientBase &operator=(TDFClientBase &&client) = delete;

      public: /// Encrypt and Decrypt
#ifndef SWIG
        /// Encrypt the data by reading from inputProvider and writing to outputProvider.
        /// \param inputProvider - InputProvider for reading the data.
        /// \param outputProvider -  OutputProvide for writing the TDF data.
        virtual void encryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) = 0;

        /// Decrypt the tdf data by reading from inputProvider and writing to outputProvider.
        /// \param inputProvider - InputProvider for reading the TDF data.
        /// \param outputProvider -  OutputProvide for writing the decrypted data.
        virtual void decryptWithIOProviders(IInputProvider& inputProvider, IOutputProvider& outputProvider) = 0;
#endif
        /// Encrypt the file to tdf format.
        /// \param tdfStorageType - The type of the tdf.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        virtual void encryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) = 0;

        /// Encrypt the bytes to tdf format.
        /// \param tdfStorageType - The type of the tdf.
        /// \return std::vector<VBYTE> - The vector containing the encrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        virtual std::vector<VBYTE> encryptData(const TDFStorageType &tdfStorageType) = 0;

        /// Decrypt file to tdf file format.
        /// \param tdfStorageType - The type of the tdf.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        virtual void decryptFile(const TDFStorageType &tdfStorageType, const std::string &outFilepath) = 0;

        /// Decrypt the bytes to tdf format.
        /// \param tdfStorageType - The type of the tdf.
        /// \return std::vector<VBYTE> - The vector containing the decrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        virtual std::vector<VBYTE> decryptData(const TDFStorageType &tdfStorageType) = 0;

        /// Decrypt part of the data from tdf storage type.
        /// \param tdfStorageType - The type of the tdf.
        /// \param offset - The offset within the plaintext to return
        /// \param length - The length of the plaintext to return
        /// \return std::vector - The vector containing the decrypted data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        virtual std::vector<VBYTE> decryptDataPartial(const TDFStorageType &tdfStorageType, size_t offset, size_t length) = 0;

        /// Allow user to add data attribute
        /// \param dataAttribute - uri of the attribute
        /// \param kasUrl - kas url
        virtual void addDataAttribute(const std::string &dataAttribute,
                              const std::string &kasURL) = 0;

    public: /// Interface
        /// Enable the internal logger class to write logs to the console for given LogLevel.
        /// The default Loglevel is 'Current' if not specified.
        /// \param logLevel - The log level
        void enableConsoleLogging(LogLevel logLevel = LogLevel::Current);

        /// Enable benchmark logging.
        void enableBenchmark();

    public: /// Policy interface(users, Attributes)
        /// Add access to the TDF file/data for the users in the list
        /// \param users - Share the TDF with the users in the vector
        void shareWithUsers(const std::vector<std::string> &users);

        /// Allow user to read entity attributes
        /// \return Return vector of entityAttributes -- unique resource locator of each attribute
        //          associated with the EntityObject for this client instance
        std::vector<std::string> getEntityAttributes();

        /// Allow user to read attributes from OIDC
        /// \return Return vector of attributes in claims object
        std::vector<std::string> getSubjectAttributes();

        ///Allow user to read data attributes associated with this instances of client (to be replaced by inspectDataAttributes)
        /// \return Return vector of dataAttributes -- unique resource locater of each data attribute
        //          associated with this client instance
        std::vector<std::string> getDataAttributes();

      protected: /// Helpers
        /// Create the policy object.
        /// \return The Policy object.
        PolicyObject createPolicyObject();

        /// Get vector of entity attribute objects
        /// \return Return vector of entity attribute objects
        virtual std::vector<AttributeObject> getEntityAttrObjects() = 0;

        /// Get vector of entity attribute objects
        /// \return Return vector of entity attribute objects
        virtual std::vector<AttributeObject> getSubjectAttrObjects() = 0;

        /// Find a default attribute object in a vector of attribute objects
        /// \param attributeObjects - a vector of attribute objects
        /// \return Return default attribute object or attribute object of empty strings
        AttributeObject getDefaultAttributeObject(const std::vector<AttributeObject> &attributeObjects);

      protected: /// Data
        std::string m_easUrl;
        std::string m_user;
        std::string m_clientKeyFileName;
        std::string m_clientCertFileName;
        std::string m_certAuthority;
        std::string m_metadata;
        std::set<std::string> m_dissems;
        std::vector<AttributeObject> m_dataAttributeObjects;
        LogLevel m_logLevel{LogLevel::Current};
        std::shared_ptr<INetwork> m_httpServiceProvider;
    };
} // namespace virtru

class tdf_client {
};

#endif //VIRTRU_TDF_CLIENT_H
