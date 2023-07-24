/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/

#ifndef VIRTRU_TDF_STORAGETYPE_H
#define VIRTRU_TDF_STORAGETYPE_H

#include <string>
#include <vector>

#include "tdf_constants.h"
#include "tdf_assertion.h"

namespace virtru {

    class TDFClient;
    class NanoTDFClient;

    class TDFStorageType{
    public:
        // Enum to define the type of the tdf file
        enum class StorageType {
            File,
            S3,
            Buffer,
            None
        };

    public:
        /// Constructor
        TDFStorageType();

        /// Destructor
        ~TDFStorageType();

        /// Assignment operator
        TDFStorageType &operator=(const TDFStorageType &oidcCredentials);

        /// Copy constructor
        TDFStorageType(const TDFStorageType &oidcCredentials);

        /// Move copy constructor
        TDFStorageType(TDFStorageType &&oidcCredentials);

        /// Move assignment operator
        TDFStorageType &operator=(TDFStorageType &&oidcCredentials);

    public:
        /// set the TDF storage type as type file.
        /// \param filePath - The file on which the tdf operations to be performed on
        void setTDFStorageFileType(const std::string& filePath);

#ifndef SWIG
        /// set the TDF storage type as type string.
        /// \param str - The str container containing data to be encrypted or decrypted.
        void setTDFStorageStringType(const std::string& str);
#endif

        /// set the TDF storage type as type buffer.
        /// \param buffer - The buffer container containing data to be encrypted or decrypted.
        void setTDFStorageBufferType(const std::vector<VBYTE>& buffer);

        /// set the TDF storage type as type S3.
        /// \param S3Url - https-prefixed URL to the object to be read
        /// \param awsAccessKeyID - Access Key ID for the AWS credentials
        /// \param awsSecretAccessKey - Secret access key for AWS credentials
        /// \param awsRegionName - Region name for AWS credentials
        void setTDFStorageS3Type(const std::string &S3Url, const std::string& awsAccessKeyId, const std::string& awsSecretAccessKey, const std::string& awsRegionName);

        /// Add the assertion to the TDF
        /// \param assertion - The assertion object
        void setAssertion(const Assertion& assertion);

        /// Return the unique, canonical descriptor/location this
        /// StorageType is pointing to.
        ///
        /// For S3, this might be a bucket URL. For file, this might be a path, etc.
        /// \return The unique/canonical/locative descriptor this StorageType instance refers to.
        std::string getStorageDescriptor() const;

        /// Return the description of this object.
        /// \return The description of this object.
        std::string str() const;

    private:
        friend TDFClient;
        friend NanoTDFClient;
        std::string                     m_filePath;
        std::string                     m_tdfBuffer;
        StorageType                     m_tdfType;
        std::string                     m_awsAccessKeyId;
        std::string                     m_awsSecretAccessKey;
        std::string                     m_awsRegionName;
        std::string                     m_S3Url;
        std::vector<Assertion>          m_assertions;
    };
}
#endif //VIRTRU_TDF_STORAGETYPE_H
