/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/04.
//

#include "tdf.h"
#include "tdf_impl.h"
#include "tdfbuilder.h"
#include "tdfbuilder_impl.h"
#include "file_io_provider.h"
#include "stream_io_provider.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <boost/filesystem.hpp>
#include "nlohmann/json.hpp"
#include <iostream>


namespace virtru {

    /// Constructor
    TDF::TDF(TDFBuilder& tdfBuilder)
    : m_impl(std::make_unique<TDFImpl>(tdfBuilder)) { }


    /// Encrypt the file to tdf format.
    void TDF::encryptFile(const std::string& inFilepath, const std::string& outFilepath) {

        LogInfo("encrypt file:" + inFilepath);

        // Create input provider
        FileInputProvider inputProvider{inFilepath};

        // Create output provider
        FileOutputProvider outputProvider{outFilepath};
        m_impl->encryptIOProvider(inputProvider, outputProvider);
    }

    /// Encrypt data from InputProvider and write to IOutputProvider
    void TDF::encryptIOProvider(IInputProvider& inputProvider, IOutputProvider& outputProvider) {
        LogInfo("encrypt io provider");

        m_impl->encryptIOProvider(inputProvider, outputProvider);
    }

    /// Encrypt data from input provider and write to ITDFWriter
    void TDF::encryptInputProviderToTDFWriter(IInputProvider& inputProvider, ITDFWriter& writer) {
        LogInfo("encrypt io provider to");

        m_impl->encryptInputProviderToTDFWriter(inputProvider, writer);
    }

    /// Encrypt the stream data to tdf format.
    void TDF::encryptStream(std::istream& inStream, std::ostream& outStream) {

        LogInfo("encrypt data in stream...");

        StreamInputProvider inputProvider{inStream};
        StreamOutputProvider outputProvider{outStream};

        m_impl->encryptIOProvider(inputProvider, outputProvider);
    }

    void TDF::decryptIOProvider(IInputProvider& inputProvider, IOutputProvider& outputProvider) {

        LogInfo("decrypt using IOProviders...");

        m_impl->decryptIOProvider(inputProvider, outputProvider);
    }

    /// Decrypt data from reader and write to output provider
    void TDF::decryptTDFReaderToOutputProvider(ITDFReader& reader, IOutputProvider& outputProvider) {
        LogInfo("decrypt using IOProviders...");

        m_impl->decryptTDFReaderToOutputProvider(reader, outputProvider);
    }

    /// Decrypt file.
    void TDF::decryptFile(const std::string& inFilepath, const std::string& outFilepath) {
        LogInfo("decrypt file:" + inFilepath);

        // Create input provider
        FileInputProvider inputProvider{inFilepath};

        // Create output provider
        FileOutputProvider outputProvider{outFilepath};
        m_impl->decryptIOProvider(inputProvider, outputProvider);
    }

    /// Decrypt the tdf stream data.
    void TDF::decryptStream(std::istream& inStream, std::ostream& outStream)  {
        
        LogInfo("decrypt data in stream...");

        StreamInputProvider inputProvider{inStream};
        StreamOutputProvider outputProvider{outStream};

        m_impl->decryptIOProvider(inputProvider, outputProvider);
    }


    /// Decrypt data starting at index and of length from input provider
    /// and write to output provider
    void TDF::decryptIOProviderPartial(IInputProvider& inputProvider,
                                       IOutputProvider& outputProvider,
                                       size_t offset,
                                       size_t length) {

        LogInfo("decrypt data in io provider...");

        m_impl->decryptIOProviderPartial(inputProvider, outputProvider, offset, length);
    }

    /// Decrypt and return TDF metadata as a string. If the TDF content has
    /// no encrypted metadata, will return an empty string.
    std::string TDF::getEncryptedMetadata(IInputProvider& inputProvider) {
        LogInfo("get metadata from tdf data stream");

        return m_impl->getEncryptedMetadata(inputProvider);
    }

    /// Extract and return the JSON policy string from the input provider.
    std::string TDF::getPolicy(IInputProvider& inputProvider) {
        LogInfo("get policy object from inputProvider...");

        return m_impl->getPolicy(inputProvider);
    }

    /// Return the policy uuid from the input provider.
    /// TODO we should consider deprecating this in favor of
    /// the more broadly-useful `getPolicy`
    std::string TDF::getPolicyUUID(IInputProvider& inputProvider) {
        LogInfo("get policy uuid from tdf input provider" );
        
        return m_impl->getPolicyUUID(inputProvider);
    }

    /// Return the policy from the tdf input stream.
    std::string TDF::getPolicy(std::istream&  inStream) {
        LogInfo("get policy object from stream...");

        StreamInputProvider inputProvider{inStream};
        return m_impl->getPolicy(inputProvider);
    }

    /// Return the policy uuid from the tdf file.
    /// TODO we should consider deprecating this in favor of
    /// the more broadly-useful `getPolicy`
    std::string TDF::getPolicyUUID(const std::string& tdfFilePath) {
        LogInfo("get policy uuid from tdf:" + tdfFilePath);

        // Create input provider
        FileInputProvider inputProvider{tdfFilePath};
        return m_impl->getPolicyUUID(inputProvider);
    }

    /// Return the policy uuid from the tdf input stream.
    /// TODO we should consider deprecating this in favor of
    /// the more broadly-useful `getPolicy`
    std::string TDF::getPolicyUUID(std::istream&  inStream) {
        LogInfo("get policy uuid from stream...");

        StreamInputProvider inputProvider{inStream};
        return m_impl->getPolicyUUID(inputProvider);
    }

    /// Sync the tdf file, with symmetric wrapped key and Policy Object.
    void TDF::sync(const std::string& encryptedTdfFilepath) {
        LogInfo("sync tdf:" + encryptedTdfFilepath);

        m_impl->sync(encryptedTdfFilepath);
    }

    /// Convert the zip formatted TDF to the xml formatted TDF(ICTDF)
    void TDF::convertXmlToJson(const std::string& ictdfFilePath, const std::string& tdfFilePath) {
        LogInfo("Convert ICTDF o TDF");

        TDFImpl::convertICTDFToTDF(ictdfFilePath, tdfFilePath);
    }

    /// Convert the json formatted TDF to xml formatted TDF(ICTDF)
    void TDF::convertJsonToXml(const std::string& tdfFilePath, const std::string& ictdfFilePath) {
        LogInfo("Convert TDF to ICTDF");

        TDFImpl::convertTDFToICTDF(tdfFilePath, ictdfFilePath);
    }

    bool TDF::isInputProviderTDF(IInputProvider& inputProvider) {
        LogInfo("check if input provider is tdf");

        return TDFImpl::isInputProviderTDF(inputProvider);
    }

    TDF::~TDF() = default;
}  // namespace virtru
