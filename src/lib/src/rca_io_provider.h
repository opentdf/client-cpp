/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*/

#ifndef VIRTRU_RCA_IO_PROVIDER_H
#define VIRTRU_RCA_IO_PROVIDER_H

#include "io_provider.h"
#include "network_interface.h"
#include <vector>
#include <queue>

namespace virtru {

    using namespace virtru::crypto;

    class RCAInputProvider: public IInputProvider {
    public:
        /// Constructor
        /// \param S3Url - https-prefixed URL to the object to be read
        RCAInputProvider(const std::string &S3Url);

        /// Destructor
        ~RCAInputProvider() = default;

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
        std::string m_url;
        HttpHeaders m_headers;
        std::shared_ptr<INetwork> m_httpServiceProvider;
    };

    class RCAOutputProvider: public IOutputProvider {
    public:
        /// Constructor
        /// \param S3Url - https-prefixed URL to the object to be read
        /// \param awsAccessKeyID - Access Key ID for the AWS credentials
        /// \param awsSecretAccessKey - Secret access key for AWS credentials
        /// \param awsRegionName - Region name for AWS credentials
        RCAOutputProvider(const std::string &S3Url, HttpHeaders headers);

        /// Destructor
        ~RCAOutputProvider() = default;

    public: // From IOutputProvider
        /// Write
        /// \param bytes - buffer containing data to be written to file
        virtual void writeBytes(Bytes bytes) override;

        /// Replace the default network provider with the supplied one - used for unit test
        void setHttpServiceProvider(std::shared_ptr<INetwork> httpServiceProvider);

        /// Force provider to flush data to destination
        virtual void flush() override;

    public:
        /// Return the remote file used to store the data
        /// \return The remote file used to store the data
        std::string remoteFileName() { return m_generatedKey; }

    private:
        /// Start the RCA service
        void startRCAService();

        /// Fetch the new links
        void fetchNewRCALinks();

        ///Finished uploading and stop the RCA service
        void finishRCAService();

        /// Copy data to remote url.
        void copyDataToRemoteURL();

    private:
        std::string m_url;
        std::string m_uploadId;
        std::string m_generatedKey;
        std::shared_ptr<INetwork> m_httpServiceProvider;
        HttpHeaders m_headers;
        std::queue<std::string> m_rcaLinks;
        std::vector<std::string> m_etags;
        std::vector<gsl::byte> m_buffer;
        std::uint32_t m_bufferSize{0};
        std::uint32_t m_nextPartNumber{1};
    };
}
#endif //VIRTRU_RCA_IO_PROVIDER_H
