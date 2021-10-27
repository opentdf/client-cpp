/*
* Copyright 2018 Virtru Corporation
*
* SPDX - License - Identifier: MIT
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
#include <memory>
#include <string>

namespace virtru {

    /// Forward declaration.
    class TDFBuilder;
    class TDFImpl;

    /// TDF should be retrieve from TDFBuilder.

    class TDF {
    public: /// Interface

        /// Encrypt the file to tdf format.
        /// \param inFilepath - The file on which the encryption is performed.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        void encryptFile(const std::string& inFilepath, const std::string& outFilepath);

#ifndef SWIG
        /// Encrypt the stream data to tdf format.
        /// \param inStream - The stream containing a data to be encrypted.
        /// \param outStream - The stream containing the encrypted data.
        void encryptStream(std::istream& inStream, std::ostream& outStream);

        /// Encrypt the data that is retrieved from the source callback.
        /// \param sourceCb - A source callback to retrieve the data to be encrypted.
        /// \param sinkCb - A sink callback with the encrypted data.
        void encryptData(TDFDataSourceCb sourceCb, TDFDataSinkCb sinkCb);
#endif

        /// Decrypt file.
        /// \param inFilepath - The file on which the decryption is performed.
        /// \param outFilepath - The file path of the tdf after successful decryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        void decryptFile(const std::string& inFilepath, const std::string& outFilepath);
        
#ifndef SWIG
        /// Decrypt the tdf stream data.
        /// \param inStream - The stream containing a tdf data to be decrypted.
        /// \param outStream - The stream containing plain data.
        void decryptStream(std::istream& inStream, std::ostream& outStream);

        /// Decrypt the data that is retrieved from the source callback.
        /// \param sourceCb - A source callback to retrieve the data to be decrypted.
        /// \param sinkCb - A sink callback with the decrypted data.
        void decryptData(TDFDataSourceCb sourceCb, TDFDataSinkCb sinkCb);
#endif

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
