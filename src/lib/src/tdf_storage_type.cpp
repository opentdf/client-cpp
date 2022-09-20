/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/

#include "tdf_storage_type.h"
#include "tdf_exception.h"
#include <sstream>

namespace virtru {

    /// Construcor
    TDFStorageType::TDFStorageType() = default;

    /// Destructor
    TDFStorageType::~TDFStorageType() = default;

    // Provide default implementation.
    TDFStorageType::TDFStorageType(const TDFStorageType &) = default;
    TDFStorageType &TDFStorageType::operator=(const TDFStorageType &) = default;
    TDFStorageType::TDFStorageType(TDFStorageType &&) = default;
    TDFStorageType &TDFStorageType::operator=(TDFStorageType &&) = default;

    /// Create an instance of TDFStorageType of type file.
    void TDFStorageType::setTDFStorageFileType(const std::string& filePath) {
        m_filePath = filePath;
        m_tdfType = StorageType::File;
    }

    /// Create an instance of TDFStorageType of type string.
    void TDFStorageType::setTDFStorageStringType(const std::string& str) {
        m_tdfBuffer.reserve(str.size());
        std::copy(str.begin(), str.end(), std::back_inserter(m_tdfBuffer));
        m_tdfType = StorageType::Buffer;
    }


    /// Create an instance of TDFStorageType of type buffer.
    void TDFStorageType::setTDFStorageBufferType(const std::vector<VBYTE>& buffer) {
        m_tdfBuffer.reserve(buffer.size());
        std::copy(buffer.begin(), buffer.end(), std::back_inserter(m_tdfBuffer));
        m_tdfType = StorageType::Buffer;
    }

    void TDFStorageType::setTDFStorageS3Type(const std::string &S3Url, const std::string& awsAccessKeyId, const std::string& awsSecretAccessKey, const std::string& awsRegionName) {
        m_tdfType = StorageType::S3;
        m_S3Url = S3Url;
        m_awsAccessKeyId = awsAccessKeyId;
        m_awsSecretAccessKey = awsSecretAccessKey;
        m_awsRegionName = awsRegionName;
    }

    /// Return the unique, canonical descriptor/location this
    /// StorageType is pointing to, so callers can distinguish between instances of TDFStorageType
    ///
    /// For S3, this might be a bucket URL. For file, this might be a path, etc.
    /// \return The unique/canonical/locative descriptor this StorageType instance refers to.
    std::string TDFStorageType::getStorageDescriptor() const  {
        std::ostringstream osRetval;

        //Return a hash of the buffer contents
        if (m_tdfType == StorageType::Buffer) {
            std::size_t bufHash = std::hash<std::string>{}(m_tdfBuffer);
            osRetval << bufHash << std::endl;
        //Return the file path
        } else if (m_tdfType == StorageType::File) {
            osRetval << m_filePath << std::endl;
        //Return the S3 path
        } else if (m_tdfType == StorageType::S3) {
            osRetval << m_S3Url << std::endl;
        } else {
            ThrowException("No descriptor for this storage type", VIRTRU_SYSTEM_ERROR);
        }

        return osRetval.str();
    }

    /// Return the description of this object.
    std::string TDFStorageType::str() const {
        std::ostringstream osRetval;

        osRetval << "TDF storage type:";
        if (m_tdfType == StorageType::Buffer) {
            osRetval << "Buffer" << std::endl;
        } else if (m_tdfType == StorageType::File) {
            osRetval << "File" << std::endl;
        } else if (m_tdfType == StorageType::S3) {
            osRetval << "S3" << std::endl;
        } else {
            osRetval << "None" << std::endl;
        }

        return osRetval.str();
    }
}

