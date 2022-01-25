/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/02
//

#ifndef VIRTRU_NANO_TDF_IMPL_H
#define VIRTRU_NANO_TDF_IMPL_H

#include "crypto/crypto_utils.h"
#include "nanotdf/header.h"
#include "sdk_constants.h"

#include <string>
#include <memory>
#include <vector>
#include <string_view>

namespace virtru {

    using namespace virtru::crypto;
    using namespace virtru::nanotdf;

    /// Forward declaration.
    class NanoTDFBuilder;

    /// Constants
    constexpr auto KNanoTDFOverhead = 70 * 1024; // 70kb, the max policy size 64kb.

    class NanoTDFImpl {
    public:
        /// Constructor
        /// \param nanoTdfBuilder - The builder which hold necessary information performing nano tdf operations.
        /// \param datasetMode - Create a instance in dataset mode.
        /// \param maxKeyIterations - Maximum number of encrypt operations before a new key is generated.
        explicit NanoTDFImpl(NanoTDFBuilder& nanoTdfBuilder, bool datasetMode = false,
                std::uint32_t maxKeyIterations = kNTDFMaxKeyIterations);

        /// Destructor
        ~NanoTDFImpl();

    public: /// Interface
        /// Encrypt the file to nano tdf format.
        /// \param inFilepath - The file on which the encryption is performed.
        /// \param outFilepath - The file path of the tdf after successful encryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        void encryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Encrypt the data to nano tdf format.
        /// \param plainData - The buffer containing a data to be encrypted.
        /// \return std::string_view - The string_view(a reference to encrypted data).
        /// NOTE: virtru::exception will be thrown if there is issues while performing the encryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view encryptString(Bytes plainData);

        /// Decrypt file the nano tdf file.
        /// \param inFilepath - The file on which the decryption is performed.
        /// \param outFilepath - The file path of the tdf after successful decryption.
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        void decryptFile(const std::string& inFilepath, const std::string& outFilepath);

        /// Decrypt data from nano tdf format.
        /// \param encryptedData - The buffer containing a data to be decrypted.
        /// \return std::string_view - The string_view(a reference to plain data).
        /// NOTE: virtru::exception will be thrown if there is issues while performing the decryption process.
        /// NOTE: The caller should copy the bytes from the return value and should not hold on to the
        /// return value.
        std::string_view decryptString(Bytes encryptedData);

    private:
        /// Create the header for encrypt.
        /// \param header The header object.
        void createHeader(Header& header);

        /// Get the symmetric key from KAS(perform rewrap operation)
        /// \param header - The header contain information required by KAS to generate a symmetric key.
        /// \return Bytes - The buffer containing symmetric key.
        std::vector<gsl::byte> getSymmetricKey(const Header& header);

        /// Generate symmetric key(without communicating with KAS, using entity private-key).
        /// \param header - The header contain information required to generate a symmetric key.
        /// \return Bytes - The buffer containing symmetric key.
        std::vector<gsl::byte> generateSymmetricKey(const Header& header) const;

        /// Check if the size is within the limit of the nano TDF
        /// \param size - The size of data.
        /// \return bool - True if size the exceed the limit of the nano TDF
        bool didExceedMaxSize(std::streampos size);

    private: // Dataset
        /// Check if rewrap is needs to decrypt the dataset TDF.
        /// \param header - The header contain information required by KAS to generate a symmetric key.
        /// \return bool - True if the dataset TDF requires a rewrap operation.
        bool needsRewrap(const Header& header);


    public: // TDF validity check
        /// Check if the file is in valid NanoTDF format.
        /// \param filePath - The NanoTDF file.
        /// \return - Return true if it's valid NanoTDF format.
        static bool isValidNanoTDFFile(const std::string& filePath);

        /// Check if the data is in valid NanoTDF format.
        /// \param nanoTDFData - The NanoTDF data
        /// \return - Return true if it's valid NanoTDF format.
        static bool isValidNanoTDFData(Bytes nanoTDFData);

    private: /// Data

        NanoTDFBuilder& m_tdfBuilder;

        // Nano TDF Information.
        Header m_header;
        std::vector<gsl::byte> m_authTag;
        std::vector<gsl::byte> m_signature;

        // Encryption internal buffer.
        std::vector<gsl::byte> m_encryptBuffer;

        // Working buffer for encrypt/decrypt.
        std::vector<gsl::byte> m_workingBuffer;

        // Decryption internal buffer.
        std::vector<gsl::byte> m_decryptBuffer;

        // Encrypt symmetric key.
        std::vector<gsl::byte> m_encryptSymmetricKey;

        // Decrypt symmetric key
        std::vector<gsl::byte> m_decryptSymmetricKey;

        // Buffer to hold the encrypted policy.
        std::vector<gsl::byte> m_policyPayload;

        std::array<gsl::byte, 32u> m_defaultSalt;

        // State to capture dataset mode.
        bool m_datasetMode{false};
        std::uint32_t m_maxKeyIterations;
        std::uint32_t m_keyIterationCount{0};
        std::uint32_t m_iv{1};
        std::vector<gsl::byte> m_cachedEphemeralKey;

        friend class NanoTDFBuilder;
    };
}

#endif // VIRTRU_NANO_TDF_IMPL_H
