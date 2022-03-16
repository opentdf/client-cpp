/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/23
//

#ifndef VIRTRU_NANOTDF_H
#define VIRTRU_NANOTDF_H

#include "tdf_constants.h"
#include <memory>
#include <string>

namespace virtru {

    /// Forward declaration.
    class NanoTDFBuilder;
    class NanoTDFImpl;

    class NanoTDF {
    public: /// Interface
        /// Encrypt the file to nano tdf format.
        /// \param inFilepath - The file on which the encryption is performed.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        void encryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Encrypt the data to nano tdf format.
        /// \param plainData - The string containing the data to be encrypted.
        /// \return std::string_view - The string_view(a reference to encrypted data).
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view encryptString(const std::string &plainData);

        /// Encrypt the bytes to nano tdf format.
        /// \param plainData - The bytes containing the data to be encrypted.
        /// \return std::string_view - The string_view(a reference to encrypted data).
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view encryptData(const std::string_view &plainData);

        /// Decrypt file the nano tdf file.
        /// \param inFilepath - The file on which the decryption is performed.
        /// \param outFilepath - The file path of the tdf after successful decryption.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        void decryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Decrypt data from nano tdf format.
        /// \param encryptedData - The string containing the data to be decrypted.
        /// \return std::string_view - The string_view(a reference to plain data).
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view decryptString(const std::string &encryptedData);

        /// Decrypt bytes from nano tdf format.
        /// \param encryptedData - The string containing the data to be decrypted.
        /// \return std::string_view - The string_view(a reference to plain data).
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view decryptData(const std::string_view &encryptedData);

        /// Destructor
        ~NanoTDF();

    private:
        friend class NanoTDFBuilder;

        /// Constructor
        /// \param tdfBuilder - The builder that holds necessary information for performing tdf operations.
        /// \param datasetMode - Create a instance in dataset mode.
        /// \param maxKeyIterations - Maximum number of encrypt operations before a new key is generated.
        explicit NanoTDF(NanoTDFBuilder& nanoTdfBuilder, bool datasetMode, std::uint32_t maxKeyIterations);

        std::unique_ptr<NanoTDFImpl> m_impl;
    };
}

#endif //VIRTRU_NANOTDF_H
