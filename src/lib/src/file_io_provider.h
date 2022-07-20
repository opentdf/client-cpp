/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*/

#ifndef VIRTRU_FILE_IO_PROVIDER_H
#define VIRTRU_FILE_IO_PROVIDER_H

#include "io_provider.h"

namespace virtru {
    class FileInputProvider: public IInputProvider {
    public:
        /// Constructor
        /// \param filePath
        FileInputProvider(const std::string &filePath);

        /// Destructor
        ~FileInputProvider();

    public: // From IInputProvider
        /// Read bytes from index to length into the buffer
        /// \param index - index within data where read is to begin
        /// \param length - length of data to be retrieved starting from index
        /// \param bytes - buffer for storing the retrieved data
        void readBytes(size_t index, size_t length, WriteableBytes &bytes) override;

        /// Return the size of the provider
        /// \return - size of the data in the file
        virtual size_t getSize() override;

    private:
        std::unique_ptr<std::ifstream> m_fileStream;
        const std::string& m_filePath;
    };

    class FileOutputProvider: public IOutputProvider {
    public:
        /// Constructor
        /// \param filePath - path to file
        FileOutputProvider(const std::string &filePath);

        /// Destructor
        ~FileOutputProvider();

    public: // From IOutputProvider
        /// Write size of bytes from the provider
        /// \param bytes - buffer containing data to be written to file
        virtual void writeBytes(Bytes bytes) override;

        /// Force flush of data to file
        virtual void flush() override;

    private:
        std::unique_ptr<std::ofstream> m_fileStream;
        const std::string& m_filePath;
    };
}
#endif //VIRTRU_FILE_IO_PROVIDER_H
