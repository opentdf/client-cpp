/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*/

#ifndef VIRTRU_IOPROVIDER_H
#define VIRTRU_IOPROVIDER_H

#include "crypto/bytes.h"

namespace virtru {

    using namespace virtru::crypto;

    class IInputProvider {
    public:
        /// Read bytes from index to length into the buffer
        /// \param index - index within data where read is to begin
        /// \param length - length of data to be retrieved starting from index
        /// \param bytes - buffer for storing the retrieved data
        virtual void readBytes(size_t index, size_t length, WriteableBytes &bytes) = 0;

        /// Return the size of the provider
        /// \return - size of the data
        virtual size_t getSize() = 0;
    };

    class IOutputProvider {
    public:
        /// Write size of bytes from the provider
        /// \param bytes - buffer containing data to be written
        virtual void writeBytes(Bytes bytes) = 0;

        /// Force provider to flush data to destination
        virtual void flush() = 0;
    };

    class IRemoteOutputProvider {
    public:
        /// Write size of bytes from the provider
        /// \param bytes - buffer containing data to be written
        virtual void writeBytes(Bytes bytes, const std::string& url) = 0;

        /// Force provider to flush data to destination
        virtual void flush() = 0;
    };
}
#endif //VIRTRU_IOPROVIDER_H

