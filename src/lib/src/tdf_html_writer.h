/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 7/5/22.
//

#ifndef VIRTRU_TDF_HTML_WRITER_H
#define VIRTRU_TDF_HTML_WRITER_H

#include <string>
#include <vector>
#include "libxml2_deleters.h"
#include "tdf_xml_reader.h"
#include "tdf_writer.h"
#include "tdf_constants.h"
#include "crypto/bytes.h"
#include "io_provider.h"
#include "tdf_archive_writer.h"

namespace virtru {

    using namespace virtru::crypto;

    class TDFHTMLWriter : public ITDFWriter {
    public:
        /// Constructor
        /// \param outputProvider - The html data will write to the output provider.
        /// \param manifestFilename - A manifest file name to be used in the TDF file (manifest.xml - TDF2,
        ///                           manifest.json - TDF).
        /// \param secureReaderUrl - Virtru secure reader URL
        /// \param payloadFileName - A payload file name to be used in the TDF file
        /// \param htmlTokens - HTML token used to build to build HTML TDF
        TDFHTMLWriter(IOutputProvider& outputProvider,
                      std::string manifestFilename,
                      std::string payloadFileName,
                      std::string secureReaderUrl,
                      std::vector<std::string>& htmlTokens);

        /// Delete default constructor
        TDFHTMLWriter() = delete;

        /// Destructor
        ~TDFHTMLWriter() override = default;

        /// Not supported.
        TDFHTMLWriter(const TDFHTMLWriter &) = delete;
        TDFHTMLWriter(TDFHTMLWriter &&) = delete;
        TDFHTMLWriter & operator=(const TDFHTMLWriter &) = delete;
        TDFHTMLWriter & operator=(TDFHTMLWriter &&) = delete;

    public: // From ITDFWriter
        /// Set the payload size of the TDF
        /// \param payloadSize
        void setPayloadSize(int64_t payloadSize) override;

        /// Append the manifest contents to the archive.
        /// \param manifest - Contents of the manifest file.
        /// NOTE: Manifest should be always be added at the end after writing the payload for TDF.
        /// NOTE: Manifest should be always be added before writing the payload for TDF2.
        void appendManifest(std::string&& manifest) override;

        /// Append the manifest contents to the archive.
        /// \param payload - encrypted payload.
        void appendPayload(Bytes payload) override;

        /// Finalize archive entry.
        void finish() override;
    private:
        /// Create HTML TDF buffer
        /// \return The xmlBuffer containing the HTML TDF
        /// NOTE: Caller is responsible for deleting the buffer
        xmlBufferPtr createTDFHTML();

    private: /// Data
        std::string                m_manifestFilename;
        std::string                m_payloadFileName;
        std::string                m_manifest;
        std::string                m_secureReaderUrl;
        std::vector<gsl::byte>     m_binaryPayload;
        std::vector<std::string>&  m_htmlTemplateTokens;
        IOutputProvider&           m_outputProvider;
    };
}



#endif //VIRTRU_TDF_HTML_WRITER_H
