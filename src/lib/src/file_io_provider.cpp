/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
* Created by Patrick Mancuso on 5/3/22.
*/

#include "file_io_provider.h"
#include "logger.h"
#include "tdf_exception.h"
#include <iostream>
#include <fstream>

namespace virtru {

    /// Constructor
    FileInputProvider::FileInputProvider(const std::string& filePath) : m_filePath{filePath} {
        LogTrace("FileInputProvider::FileInputProvider");
        m_fileStream = std::make_unique<std::ifstream>(m_filePath, std::ios_base::binary | std::ios_base::in);
        if (m_fileStream->fail()) {
            std::string errorMsg{"fileStream create failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
        m_fileStream->exceptions(::std::ios_base::failbit | ::std::ios_base::badbit | ::std::ios_base::eofbit);
    }

    /// Destructor
    FileInputProvider::~FileInputProvider() {
        m_fileStream->close();
    }

    /// Read bytes from index to length into the buffer
    void FileInputProvider::readBytes(size_t index, size_t length, WriteableBytes& bytes) {
        LogTrace("FileInputProvider::readBytes");

        if (static_cast<size_t >(bytes.size()) < length) {
            std::string errorMsg{"Buffer not large enough for requested length"};
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        m_fileStream->seekg(index);
        if (m_fileStream->fail()) {
            std::string errorMsg{"fileStream seekg failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        m_fileStream->read(toChar(bytes.data()), length);
        if (m_fileStream->fail()) {
            std::string errorMsg{"fileStream read failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);        }
    };

    /// Return the size of the provider
    size_t FileInputProvider::getSize() {
        LogTrace("FileOutputProvider::getSize");
        m_fileStream->seekg( 0, std::ios_base::end );
        return m_fileStream->tellg();
    }

    /// Constructor
    FileOutputProvider::FileOutputProvider(const std::string& filePath) : m_filePath{filePath} {
        LogTrace("FileOutputProvider::FileOutputProvider");
        m_fileStream = std::make_unique<std::ofstream>(m_filePath, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
        if (m_fileStream->fail()) {
            std::string errorMsg{"fileStream create failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
        m_fileStream->exceptions(::std::ios_base::failbit | ::std::ios_base::badbit | ::std::ios_base::eofbit);
    }

    void FileOutputProvider::writeBytes(Bytes bytes) {
        LogTrace("FileOutputProvider::writeBytes");

        m_fileStream->write(toChar(bytes.data()), bytes.size());
        if (m_fileStream->fail()) {
            std::string errorMsg{"fileStream write failed"};
            LogDebug(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }
    };

    /// Flush data out to file
    void FileOutputProvider::flush() {
        m_fileStream->flush();
    }

    /// Destructor
    FileOutputProvider::~FileOutputProvider() {
        m_fileStream->close();
    }
}
