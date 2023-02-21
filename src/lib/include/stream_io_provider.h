/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*/

#ifndef VIRTRU_SSTREAM_IO_PROVIDER_H
#define VIRTRU_SSTREAM_IO_PROVIDER_H

#include "io_provider.h"

#include <sstream>

namespace virtru {

    class StreamInputProvider : public IInputProvider {
    public:
        /// Constructor
        /// \param stream The stream on which input operations are performed
        StreamInputProvider(std::istream &stream);

        /// Destructor
        ~StreamInputProvider() = default;

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
        std::istream &m_istream;
    };


    class StreamOutputProvider : public IOutputProvider {
    public:
        /// Constructor
        /// \param stream The stream on which output operations are performed
        StreamOutputProvider(std::ostream &stream);

        /// Destructor
        ~StreamOutputProvider() = default;

    public: // From IOutputProvider
        /// Write size of bytes from the provider
        /// \param bytes - buffer containing data to be written to file
        virtual void writeBytes(Bytes bytes) override;

        /// Force provider to flush data to destination
        virtual void flush() override {};

    private:
        std::ostream &m_ostream;
    };
}

#endif //VIRTRU_SSTREAM_IO_PROVIDER_H
