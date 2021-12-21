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

namespace virtru {

    using namespace virtru::crypto;

    class TDFXMLReader : public TDFReader {
    public:
        /// Constructor
        /// \param inStream - A source input stream which hold the xml data.
        TDFXMLReader(std::istream& inStream);

        /// Delete default constructor
        TDFXMLReader() = delete;

        /// Destructor
        ~TDFXMLReader() override = default;

        /// Not supported.
        TDFXMLReader(const TDFXMLReader &) = delete;
        TDFXMLReader(TDFXMLReader &&) = delete;
        TDFXMLReader & operator=(const TDFXMLReader &) = delete;
        TDFXMLReader & operator=(TDFXMLReader &&) = delete;

    public: // From TDFWriter
        /// Get the manifest content.
        /// \return - Return the manifest as string.
        const std::string& getManifest() override;

        /// Read the payload contents into the buffer.
        /// The size of buffer could be less than requested size.
        /// \param buffer - WriteableBytes
        void readPayload(WriteableBytes& buffer) override;

        /// Get the size of the payload.
        /// \return std::uint64_t - Size of the payload.
        std::int64_t getPayloadSize() const override;

    private: /// Data
        std::istream&           m_inStream;
        std::string             m_manifest;
        std::vector<gsl::byte>  m_binaryPayload;
        std::size_t             m_payloadLeftToRead;
        std::size_t             m_payloadStartIndex{0};
    };
}

#endif //VIRTRU_TDF_XML_READER_H
