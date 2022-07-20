/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/10/21.
//

#ifndef VIRTRU_TDF_XML_READER_H
#define VIRTRU_TDF_XML_READER_H

#include <string>
#include <vector>
#include <istream>
#include "tdf_reader.h"
#include "tdf_constants.h"
#include "crypto/bytes.h"
#include "io_provider.h"
#include "tdf_archive_reader.h"

namespace virtru {

    using namespace virtru::crypto;

    class TDFXMLReader : public ITDFReader {
    public:
        /// Constructor
        /// \param inputProvider -  A input provider which hold the xml data.
        TDFXMLReader(IInputProvider& inputProvider);

        /// Delete default constructor
        TDFXMLReader() = delete;

        /// Destructor
        ~TDFXMLReader() override = default;

        /// Not supported.
        TDFXMLReader(const TDFXMLReader &) = delete;
        TDFXMLReader(TDFXMLReader &&) = delete;
        TDFXMLReader & operator=(const TDFXMLReader &) = delete;
        TDFXMLReader & operator=(TDFXMLReader &&) = delete;

    public: // From ITDFReader
        /// Get the manifest content.
        /// \return - Return the manifest as string.
        const std::string& getManifest() override;

        /// Read payload of length starting the index.
        /// \param index - index within data where read is to begin
        /// \param length - length of data to be retrieved starting from index
        /// \param bytes - buffer for storing the retrieved data
        void readPayload(size_t index, size_t length, WriteableBytes &bytes) override;

        /// Get the size of the payload.
        /// \return std::uint64_t - Size of the payload.
        std::uint64_t getPayloadSize() const override;

    private: /// Data
        IInputProvider&         m_inputProvider;
        std::string             m_manifest;
        std::vector<gsl::byte>  m_binaryPayload;
    };
}

#endif //VIRTRU_TDF_XML_READER_H
