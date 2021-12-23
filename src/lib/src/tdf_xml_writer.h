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

namespace virtru {

    using namespace virtru::crypto;

    class TDFXMLWriter : public TDFWriter {
    public:
        /// Constructor
        /// \param manifestFilename - A manifest file name to be used in the TDF file (manifest.xml - TDF2,
        ///                           manifest.json - TDF).
        /// \param payloadFileName - A payload file name to be used in the TDF file
        TDFXMLWriter(std::string manifestFilename, std::string payloadFileName);

        /// Delete default constructor
        TDFXMLWriter() = delete;

        /// Destructor
        ~TDFXMLWriter() override = default;

        /// Not supported.
        TDFXMLWriter(const TDFXMLWriter &) = delete;
        TDFXMLWriter(TDFXMLWriter &&) = delete;
        TDFXMLWriter & operator=(const TDFXMLWriter &) = delete;
        TDFXMLWriter & operator=(TDFXMLWriter &&) = delete;

    public: // From TDFWriter
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

    public:
        /// Write the XML TDF to the output stream
        /// \param outStream - The output stream
        void writeToStream(std::ostream& outStream);

    private: /// Data
        std::string             m_manifestFilename;
        std::string             m_payloadFileName;
        std::string             m_manifest;
        std::vector<gsl::byte>  m_binaryPayload;
    };
}



#endif //VIRTRU_TDF_XML_WRITER_H
