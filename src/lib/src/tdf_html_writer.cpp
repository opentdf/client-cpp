/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 7/5/22.
//

#include <regex>
#include "logger.h"
#include "tdf_constants.h"
#include "sdk_constants.h"
#include "tdf_exception.h"
#include "tdf_html_writer.h"

#include <boost/beast/core/detail/base64.hpp>

namespace virtru {

    using namespace boost::beast::detail::base64;

    /// Constructor for TDFXMLWriter
    TDFHTMLWriter::TDFHTMLWriter(IOutputProvider& outputProvider, std::string manifestFilename,
                                 std::string payloadFileName, std::string secureReaderUrl,
                                 std::vector<std::string>& htmlTokens)
            : m_manifestFilename{std::move(manifestFilename)},
            m_payloadFileName{std::move(payloadFileName)},
            m_secureReaderUrl{std::move(secureReaderUrl)},
            m_htmlTemplateTokens(htmlTokens),
            m_outputProvider(outputProvider) {
    }

    /// Set the payload size of the TDF
    void TDFHTMLWriter::setPayloadSize(int64_t payloadSize)  {
        m_binaryPayload.reserve(payloadSize);
    }

    /// Append the manifest contents to the archive.
    void TDFHTMLWriter::appendManifest(std::string&& manifest) {
        m_manifest = std::move(manifest);
    }

    /// Append the manifest contents to the archive.
    void TDFHTMLWriter::appendPayload(crypto::Bytes payload) {
        m_binaryPayload.insert(m_binaryPayload.end(), payload.begin(), payload.end());
    }

    /// Finalize archive entry.
    void TDFHTMLWriter::finish() {

        auto const &token1 = m_htmlTemplateTokens[0];
        LogTrace("before token1 write");
        auto bytes = gsl::make_span(token1.data(), token1.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        /// 1 - Write the contents of the tdf in base64
        std::vector<std::uint8_t> m_encodeBufferSize(encoded_size(m_binaryPayload.size()));

        // Encode the tdf zip data.
        auto actualEncodedBufSize = encode(m_encodeBufferSize.data(),
                                                  m_binaryPayload.data(),
                                                  m_binaryPayload.size());

        m_outputProvider.writeBytes(toBytes(m_encodeBufferSize));

        auto const &token2 = m_htmlTemplateTokens[1];
        bytes = gsl::make_span(token2.data(), token2.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        /// 2 - Write the contents of the manifest in base64
        // manifest can grow larger than our prealloc'ed buffer, correct that if it's a problem
        unsigned manifestEncodedSize = encoded_size(m_manifest.size());
        if (manifestEncodedSize > m_encodeBufferSize.size()) {
            m_encodeBufferSize.resize(manifestEncodedSize);
        }

        actualEncodedBufSize = encode(m_encodeBufferSize.data(),
                                      m_manifest.data(),
                                      m_manifest.size());

        auto manifestBytes = gsl::make_span(m_encodeBufferSize.data(),
                                            actualEncodedBufSize);
        m_outputProvider.writeBytes(toBytes(manifestBytes));

        auto const &token3 = m_htmlTemplateTokens[2];
        bytes = gsl::make_span(token3.data(), token3.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        /// 3 - Write the secure reader url.
        const auto &url = m_secureReaderUrl;
        bytes = gsl::make_span(url.data(), url.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        auto const &token4 = m_htmlTemplateTokens[3];
        bytes = gsl::make_span(token4.data(), token4.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        /// 4 - Write the secure reader base url.
        std::regex urlRegex("(http|https)://([^/ ]+)(/?[^ ]*)");
        std::cmatch what;
        if (!regex_match(url.c_str(), what, urlRegex)) {
            std::string errorMsg{"Failed to parse url, expected:'(http|https)//<domain>/<target>' actual:"};
            errorMsg.append(url);
            ThrowException(std::move(errorMsg));
        }

        std::ostringstream targetBaseUrl;
        targetBaseUrl << std::string(what[1].first, what[1].second) << "://";
        targetBaseUrl << std::string(what[2].first, what[2].second);

        auto targetBaseUrlStr = targetBaseUrl.str();
        bytes = gsl::make_span(targetBaseUrlStr.data(), targetBaseUrlStr.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        auto const &token5 = m_htmlTemplateTokens[4];
        bytes = gsl::make_span(token5.data(), token5.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        /// 5 - Write he secure reader url for window.location.href - 1
        bytes = gsl::make_span(url.data(), url.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        auto const &token6 = m_htmlTemplateTokens[5];
        bytes = gsl::make_span(token6.data(), token6.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        /// 6 - Write he secure reader url for window.location.href - 2
        bytes = gsl::make_span(url.data(), url.size());
        m_outputProvider.writeBytes(toBytes(bytes));

        auto const &token7 = m_htmlTemplateTokens[6];
        bytes = gsl::make_span(token7.data(), token7.size());
        m_outputProvider.writeBytes(toBytes(bytes));
    }
}
