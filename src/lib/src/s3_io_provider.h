/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*/

#ifndef VIRTRU_S3_IO_PROVIDER_H
#define VIRTRU_S3_IO_PROVIDER_H

#include "io_provider.h"
#include "network_interface.h"

namespace virtru {
    class S3Utilities {
    public:
        /// Create the AWS signature string from the supplied input
        static std::string generateAwsSignature(const std::string& secret, const std::string& date, const std::string& region, const std::string& service, const std::string& request, const std::string& toSign);

        /// Use the supplied credentials to create the appropriate signed headers for the request
        /// \param httpVerb - GET or HEAD typically
        /// \param headers - Headers where signature should be added
        /// \param url - Url being contacted
        /// \param awsAccessKeyId - AWS credentials - Access Key ID
        /// \param awsSecretAccessKey - AWS credentials - Secret Access Key
        /// \param awsRegionName - AWS region name
        static void signHeaders(const char* httpVerb, HttpHeaders& headers, std::string url, std::string content, std::string awsAccessKeyId, std::string awsSecretAccessKey, std::string awsRegionName);
    };

    class S3InputProvider: public IInputProvider {
    public:
        /// Constructor
        /// \param S3Url - https-prefixed URL to the object to be read
        /// \param awsAccessKeyID - Access Key ID for the AWS credentials
        /// \param awsSecretAccessKey - Secret access key for AWS credentials
        /// \param awsRegionName - Region name for AWS credentials
        S3InputProvider(const std::string &S3Url, const std::string& awsAccessKeyId, const std::string& awsSecretAccessKey, const std::string& awsRegionName);

        /// Destructor
        ~S3InputProvider() = default;

    public: // From IInputProvider
        /// Read
        /// \param index - index within data where read is to begin
        /// \param length - length of data to be retrieved starting from index
        /// \param bytes - buffer for storing the retrieved data
        void readBytes(size_t index, size_t length, WriteableBytes &bytes) override;

        /// getSize
        /// \return - size of the data in the file
        virtual size_t getSize() override;

        /// Replace the default network provider with the supplied one - used for unit test
        void setHttpServiceProvider(std::shared_ptr<INetwork> httpServiceProvider);

    private:
        const std::string& m_url;
        HttpHeaders m_headers;
        std::shared_ptr<INetwork> m_httpServiceProvider;
        const std::string m_awsAccessKeyId;
        const std::string m_awsSecretAccessKey;
        const std::string m_awsRegionName;
    };

    class S3OutputProvider: public IOutputProvider {
    public:
        /// Constructor
        /// \param S3Url - https-prefixed URL to the object to be read
        /// \param awsAccessKeyID - Access Key ID for the AWS credentials
        /// \param awsSecretAccessKey - Secret access key for AWS credentials
        /// \param awsRegionName - Region name for AWS credentials
        S3OutputProvider(const std::string &S3Url, const std::string& awsAccessKeyId, const std::string& awsSecretAccessKey, const std::string& awsRegionName);

        /// Destructor
        ~S3OutputProvider() = default;

    public: // From IOutputProvider
        /// Write
        /// \param bytes - buffer containing data to be written to file
        virtual void writeBytes(Bytes bytes) override;

        /// Replace the default network provider with the supplied one - used for unit test
        void setHttpServiceProvider(std::shared_ptr<INetwork> httpServiceProvider);

        /// Force provider to flush data to destination
        virtual void flush() override {};

    private:
        const std::string& m_url;
        std::shared_ptr<INetwork> m_httpServiceProvider;
        HttpHeaders m_headers;
        const std::string m_awsAccessKeyId;
        const std::string m_awsSecretAccessKey;
        const std::string m_awsRegionName;
    };
}
#endif //VIRTRU_S3_IO_PROVIDER_H
