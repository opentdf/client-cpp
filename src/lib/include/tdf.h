/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/02/28.
//

#ifndef VIRTRU_TDF_H
#define VIRTRU_TDF_H

#include "tdf_constants.h"
#include "io_provider.h"
#include "tdf_storage_type.h"
#include "io_provider.h"
#include <memory>
#include <string>

namespace virtru {

    /// Forward declaration.
    class TDFBuilder;
    class TDFImpl;
    class ITDFWriter;
    class ITDFReader;

    /// TDF should be retrieve from TDFBuilder.

    class TDF {
    public: /// Interface

        /// Encrypt the file to tdf format.
        /// \param inFilepath - The file on which the encryption is performed.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        void encryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Encrypt data from InputProvider and write to IOutputProvider
        /// \param inputProvider - Input provider interface for reading data
        /// \param outputProvider - Out provider interface for writing data
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        void encryptIOProvider(IInputProvider& inputProvider, IOutputProvider& outputProvider);

#ifndef SWIG
        /// Encrypt the stream data to tdf format.
        /// \param inStream - The stream containing a data to be encrypted.
        /// \param outStream - The stream containing the encrypted data.
        void encryptStream(std::istream& inStream, std::ostream& outStream);
#endif

        /// Decrypt file.
        /// \param inFilepath - The file on which the decryption is performed.
        /// \param outFilepath - The file path of the tdf after successful decryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        void decryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Encrypt data from InputProvider and write to IOutputProvider
        /// \param inputProvider - Input provider interface for reading data
        /// \param outputProvider - Out provider interface for writing data
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        void decryptIOProvider(IInputProvider& inputProvider, IOutputProvider& outputProvider);

#ifndef SWIG
        /// Decrypt the tdf stream data.
        /// \param inStream - The stream containing a tdf data to be decrypted.
        /// \param outStream - The stream containing plain data.
        void decryptStream(std::istream &inStream, std::ostream &outStream);

        /// Decrypt data starting at index and of length from input provider
        /// and write to output provider
        /// \param inputProvider - Input provider interface for reading data
        /// \param outputProvider - Out provider interface for writing data
        /// \param offset - The offset within the plaintext to return
        /// \param length - The length of the plaintext to return
        /// \return std::string - The string containing the plain data.
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        void decryptIOProviderPartial(IInputProvider& inputProvider,
                                      IOutputProvider& outputProvider,
                                      size_t offset,
                                      size_t length);

#endif
        /// Decrypt and return TDF metadata as a string. If the TDF content has
        /// no encrypted metadata, will return an empty string.
        /// \param inputProvider - Input provider interface for reading data
        /// \return std::string - The string containing the metadata.
        std::string getEncryptedMetadata(IInputProvider& inputProvider);

        /// Extract and return the JSON policy string from the input provider.
        /// \param inputProvider - Input provider interface for reading data
        /// \return std::string - The string containing the policy.
        /// NOTE: virtru::exception will be thrown if there are issues while retrieving the policy.
        std::string getPolicy(IInputProvider& inputProvider);

        /// Return the policy uuid from the input provider.
        /// \param inputProvider - Input provider interface for reading data
        /// \return - Return a uuid of the policy.
        std::string getPolicyUUID(IInputProvider& inputProvider);

        /// Extract and return the JSON policy string from a TDF stream.
        /// \param inStream - The stream containing tdf data.
        /// NOTE: virtru::exception will be thrown if there are issues while retrieving the policy.
        std::string getPolicy(std::istream& inStream);

        /// Return the policy uuid from the tdf file.
        /// \param tdfFilePath - The tdf file path
        /// \return - Return a uuid of the policy.
        /// NOTE: virtru::exception will be thrown if there is issues while retrieving the policy uuid.
        std::string getPolicyUUID(const std::string& tdfFilePath);

        /// Return the policy uuid from the tdf input stream.
        /// \param inStream - The stream containing a tdf data.
        /// \return - Return a uuid of the policy.
        /// NOTE: virtru::exception will be thrown if there is issues while retrieving the policy uuid.
        std::string getPolicyUUID(std::istream&  inStream);

        /// Sync the tdf file, with symmetric wrapped key and Policy Object.
        /// \param encryptedTdfFilepath - The file path to the tdf.
        void sync(const std::string& encryptedTdfFilepath);

        /// Extract and return key access objects in TDF
        /// \param inputProvider - The input provider containing a tdf data.
        /// \return Json key access objects from a TDF
        static std::string getKeyAccessObjects(IInputProvider& inputProvider);

        /// Check if data in the input provider is TDF
        /// \param inputProvider - The input provider containing a tdf data to be decrypted.
        /// \return Return true if data is TDF and false otherwise
        static bool isInputProviderTDF(IInputProvider& inputProvider);

        /// Convert the xml formatted TDF(ICTDF) to the json formatted TDF
        /// \param ictdfFilePath -  The xml formatted TDF file path
        /// \param tdfFilePath - The zip formatted TDF file path
        static void convertXmlToJson(const std::string& ictdfFilePath, const std::string& tdfFilePath);

        /// Convert the json formatted TDF to xml formatted TDF(ICTDF)
        /// \param tdfFilePath - The zip formatted TDF file path
        /// \param ictdfFilePath -  The json formatted TDF file path
        static void convertJsonToXml(const std::string& tdfFilePath, const std::string& ictdfFilePath);

        /// Destructor
        ~TDF();

    private:
        friend class TDFBuilder;
        friend class VirtruTDF;
        
        /// Constructor
        /// \param tdfBuilder - The builder which hold necessary information performing tdf operations.
        explicit TDF(TDFBuilder& tdfBuilder);

        std::unique_ptr<TDFImpl> m_impl;
    };
}  // namespace virtru


#endif // VIRTRU_TDF_H
