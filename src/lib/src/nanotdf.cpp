/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/23
//

#include <memory>
#include <string>

#include "nanotdf_impl.h"
#include "nanotdf.h"

namespace virtru {

    /// Constructor
    NanoTDF::NanoTDF(NanoTDFBuilder& nanoTdfBuilder, bool datasetMode, std::uint32_t maxKeyIterations)
            : m_impl(std::make_unique<NanoTDFImpl>(nanoTdfBuilder, datasetMode, maxKeyIterations)) { }

    /// Encrypt the file to nano tdf format.
    void NanoTDF::encryptFile(const std::string& inFilepath, const std::string& outFilepath) {
        return m_impl->encryptFile(inFilepath, outFilepath);
    }

    /// Encrypt the data to nano tdf format.
    std::string_view NanoTDF::encryptString(const std::string &plainData) {
        return m_impl->encryptString(toBytes(plainData));
    }

    /// Encrypt the bytes to nano tdf format.
    std::string_view NanoTDF::encryptData(const std::string_view &plainData) {
        return m_impl->encryptString(toBytes(plainData));
    }

    /// Decrypt file the nano tdf file.
    void NanoTDF::decryptFile(const std::string& inFilepath, const std::string& outFilepath) {
        return m_impl->decryptFile(inFilepath, outFilepath);
    }

    /// Decrypt data from nano tdf format.
    std::string_view NanoTDF::decryptString(const std::string& encryptedData) {
        return m_impl->decryptString(toBytes(encryptedData));
    }

    /// Decrypt bytes from nano tdf format.
    std::string_view NanoTDF::decryptData(const std::string_view &encryptedData) {
        return m_impl->decryptString(toBytes(encryptedData));
    }

    /// Destructor
    NanoTDF::~NanoTDF() = default;
}
