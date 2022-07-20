/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*/

#include "stream_io_provider.h"
#include "logger.h"
#include "tdf_exception.h"

namespace virtru {

    /// Constructor
    StreamInputProvider::StreamInputProvider(std::istream &stream) : m_istream{stream} { }

    /// Read bytes from index to length into the buffer
    void StreamInputProvider::readBytes(size_t index, size_t length, WriteableBytes& bytes) {
        LogTrace("SStreamInputProvider::readBytes");

        if (static_cast<size_t >(bytes.size()) < length) {
            std::string errorMsg{"Buffer not large enough for requested length"};
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        m_istream.seekg(index);
        if (m_istream.fail()) {
            std::string errorMsg{"string stream seekg failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        m_istream.read(toChar(bytes.data()), length);
        if (m_istream.fail()) {
            std::string errorMsg{"string stream read failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);        }
    };

    /// Return the size of the provider
    size_t StreamInputProvider::getSize() {
        LogTrace("SStreamInputProvider::getSize");
        m_istream.seekg( 0, std::ios_base::end );
        return m_istream.tellg();
    }


    /// Constructor
    StreamOutputProvider::StreamOutputProvider(std::ostream &stream) : m_ostream{stream} { }

    /// Write size of bytes from the provider
    void StreamOutputProvider::writeBytes(Bytes bytes) {
        LogTrace("SStreamOutputProvider::writeBytes");

        m_ostream.write(toChar(bytes.data()), bytes.size());
        if (m_ostream.fail()) {
            std::string errorMsg{"string stream write failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
    };

}
