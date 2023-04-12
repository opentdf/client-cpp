/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/8/21.
//

#ifndef VIRTRU_TDF_XML_WRITER_H
#define VIRTRU_TDF_XML_WRITER_H

#include <string>
#include <vector>
#include "tdf_writer.h"
#include "tdf_constants.h"
#include "crypto/bytes.h"
#include "io_provider.h"
#include "libxml2_deleters.h"
#include "tdf_archive_writer.h"

namespace virtru {

    using namespace virtru::crypto;

    class TDFXMLWriter : public ITDFWriter {
    public:
        /// Constructor
        /// \param manifestFilename - A manifest file name to be used in the TDF file (manifest.xml - TDF2,
        ///                           manifest.json - TDF).
        /// \param payloadFileName - A payload file name to be used in the TDF file
        TDFXMLWriter(IOutputProvider& outputProvider, std::string manifestFilename, std::string payloadFileName);

        /// Delete default constructor
        TDFXMLWriter() = delete;

        /// Destructor
        ~TDFXMLWriter() override = default;

        /// Not supported.
        TDFXMLWriter(const TDFXMLWriter &) = delete;
        TDFXMLWriter(TDFXMLWriter &&) = delete;
        TDFXMLWriter & operator=(const TDFXMLWriter &) = delete;
        TDFXMLWriter & operator=(TDFXMLWriter &&) = delete;

    public: // From ITDFWriter
        /// Set the payload size of the TDF
        /// \param payloadSize
        void setPayloadSize(int64_t payloadSize) override;

        /// Append the manifest contents to the XML output source.
        /// \param manifestDataModel - Data model containing the manifest data.
        void appendManifest(ManifestDataModel manifestDataModel) override;

        /// Append the payload contents to the XML output source.
        /// \param payload - encrypted payload.
        void appendPayload(Bytes payload) override;

        /// Finalize archive entry.
        void finish() override;

    private:
        /// Create XML TDF buffer
        /// \return The xmlBuffer containing the TDF
        /// NOTE: Caller is responsible for deleting the buffer
        xmlBufferPtr createTDFXML();

    private: /// Data
        std::string             m_manifestFilename;
        std::string             m_payloadFileName;
        std::string             m_manifest;
        std::vector<gsl::byte>  m_binaryPayload;
        IOutputProvider&        m_outputProvider;
    };
}



#endif //VIRTRU_TDF_XML_WRITER_H
