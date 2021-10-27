//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/04.
//  Copyright 2019 Virtru Corporation
//

#include "tdf.h"
#include "tdf_impl.h"
#include "tdfbuilder.h"
#include "tdfbuilder_impl.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <boost/filesystem.hpp>
#include <tao/json.hpp>
#include <iostream>


namespace virtru {

    /// Constructor
    TDF::TDF(TDFBuilder& tdfBuilder)
    : m_impl(std::make_unique<TDFImpl>(tdfBuilder)) { }


    /// Encrypt the file to tdf format.
    void TDF::encryptFile(const std::string& inFilepath, const std::string& outFilepath) {

        LogInfo("encrypt file:" + inFilepath);

        m_impl->encryptFile(inFilepath, outFilepath);
    }

    /// Encrypt the stream data to tdf format.
    void TDF::encryptStream(std::istream& inStream, std::ostream& outStream) {

        LogInfo("encrypt data in stream...");

        m_impl->encryptStream(inStream, outStream);
    }


    /// Encrypt the data that is retrieved from the source callback.
    void TDF::encryptData(TDFDataSourceCb sourceCb, TDFDataSinkCb sinkCb) {

        LogInfo("encrypt data from data source...");

        m_impl->encryptData(sourceCb, sinkCb);
    }

    /// Decrypt file.
    void TDF::decryptFile(const std::string& inFilepath, const std::string& outFilepath) {
        LogInfo("decrypt file:" + inFilepath);

        m_impl->decryptFile(inFilepath, outFilepath);
    }
    
    /// Decrypt the tdf stream data.
    void TDF::decryptStream(std::istream& inStream, std::ostream& outStream)  {
        
        LogInfo("decrypt data in stream...");
        
        m_impl->decryptStream(inStream, outStream);
    }

    /// Decrypt the data that is retrieved from the source callback.
    void TDF::decryptData(TDFDataSourceCb sourceCb, TDFDataSinkCb sinkCb) {
        LogInfo("decrypt data from data source...");

        m_impl->decryptData(sourceCb, sinkCb);
    }

    /// Return the policy uuid from the tdf file.
    std::string TDF::getPolicyUUID(const std::string& tdfFilePath) {
        LogInfo("get policy uuid from tdf:" + tdfFilePath);
        
        return m_impl->getPolicyUUID(tdfFilePath);
    }

    /// Return the policy uuid from the tdf input stream.
    std::string TDF::getPolicyUUID(std::istream&  inStream) {
        LogInfo("get policy uuid from stream...");

        return m_impl->getPolicyUUID(inStream);
    }

    /// Sync the tdf file, with symmetric wrapped key and Policy Object.
    void TDF::sync(const std::string& encryptedTdfFilepath) {
        LogInfo("sync tdf:" + encryptedTdfFilepath);

        m_impl->sync(encryptedTdfFilepath);
    }

    TDF::~TDF() = default;
}  // namespace virtru
