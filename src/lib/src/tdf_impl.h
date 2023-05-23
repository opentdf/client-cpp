/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/29
//

#ifndef VIRTRU_TDF_IMPL_H
#define VIRTRU_TDF_IMPL_H

#include "crypto/bytes.h"
#include "tdf_constants.h"
#include "tdf_archive_reader.h"
#include "libxml2_deleters.h"
#include "tdf_storage_type.h"

#include <boost/filesystem.hpp>
#include "nlohmann/json.hpp"
#include "manifest_data_model.h"

namespace virtru {

    using namespace virtru::crypto;

    /// Forward declaration
    class TDFBuilder;
    class TDFWriter;
    class SplitKey;
    class TDFZIPReader;
    class ITDFWriter;

    /// Implementation of the core functionality of tdf.
    class TDFImpl {
    public: /// Interface.
        /// Constructor
        /// \param tdfBuilder - The TDFBuilder instance.
        explicit TDFImpl(TDFBuilder& tdfBuilder);

        /// Destructor
        ~TDFImpl() = default;

        /// Encrypt data from InputProvider and write to IOutputProvider
        /// \param inputProvider - Input provider interface for reading data
        /// \param outputProvider - Out provider interface for writing data
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        void encryptIOProvider(IInputProvider& inputProvider,
                               IOutputProvider& outputProvider);

        /// Encrypt data from input provider and write to ITDFWriter
        /// \param inputProvider - Input provider interface for reading data
        /// \param writer - The writer to which tdf data will write to
        /// NOTE: virtru::exception will be thrown if there are issues while performing the encryption process.
        void encryptInputProviderToTDFWriter(IInputProvider& inputProvider, ITDFWriter& writer);

        /// Decrypt data from InputProvider and write to IOutputProvider
        /// \param inputProvider - Input provider interface for reading data
        /// \param outputProvider - Out provider interface for writing data
        /// NOTE: virtru::exception will be thrown if there are issues while performing the decryption process.
        void decryptIOProvider(IInputProvider& inputProvider,
                               IOutputProvider& outputProvider);

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

        /// Decrypt data from reader and write to output provider
        /// \param reader - TDF reader from which tdf data can be read
        /// \param outputProvider - The decrypted data will be write to output provider
        void decryptTDFReaderToOutputProvider(ITDFReader& reader, IOutputProvider& outputProvider);

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

        /// Sync the tdf file, with symmetric wrapped key and Policy Object.
        /// \param encryptedTdfFilepath - The file path to the tdf.
        void sync(const std::string& encryptedTdfFilepath) const;

        /// Check if data in the input provider is TDF
        /// \param inputProvider - The input provider containing a tdf data to be decrypted.
        /// \return Return true if data is TDF and false otherwise
        static bool isInputProviderTDF(IInputProvider& inputProvider);

        /// Convert the xml formatted TDF(ICTDF) to the json formatted TDF
        /// \param ictdfFilePath -  The xml formatted TDF file path
        /// \param tdfFilePath - The zip formatted TDF file path
        static void convertICTDFToTDF(const std::string& ictdfFilePath, const std::string& tdfFilePath);

        /// Convert the json formatted TDF to xml formatted TDF(ICTDF)
        /// \param tdfFilePath - The zip formatted TDF file path
        /// \param ictdfFilePath -  The json formatted TDF file path
        static void convertTDFToICTDF(const std::string& tdfFilePath, const std::string& ictdfFilePath);

    private:
        /// Generate a signature of the payload base on integrity algorithm.
        /// \param payload - A payload data
        /// \param splitkey - SplitKey object holding the wrapped key.
        /// \param alg - Integrity algorithm to be used for performing signature.
        /// \return string - Result of the signature calculation.
        std::string getSignature(Bytes payload, SplitKey& splitkey, IntegrityAlgorithm alg) const ;

        /// Generate a signature of the payload base on integrity algorithm.
        /// \param payload - A payload data
        /// \param splitkey - SplitKey object holding the wrapped key.
        /// \param alg - Integrity algorithm as string to be used for performing signature.
        /// \return string - Result of the signature calculation.
        std::string getSignature(Bytes payload, SplitKey& splitkey, const std::string& alg) const;

        /// Build an Upsert v2 payload based on the manifest
        /// \param requestPayload - A payload object with policy and key access already added
        /// \return string - The signed jwt
        std::string buildUpsertV2Payload(nlohmann::json& requestPayload) const;

        /// Build an Upsert v1 payload based on the manifest
        /// \param requestPayload - A payload object with policy and key access already added
        void buildUpsertV1Payload(nlohmann::json& requestPayload) const;

        /// Build a Rewrap v2 payload based on the manifest
        /// \param requestPayload - A payload object with policy and key access already added
        /// \return string - The signed jwt
        std::string buildRewrapV2Payload(nlohmann::json& requestPayload) const;

        /// Build a Rewrap v1 payload based on the manifest
        /// \param requestPayload - A payload object with policy and key access already added
        void buildRewrapV1Payload(nlohmann::json& requestPayload) const;

        /// Upsert the key information.
        /// \param manifestDataModel - Data model contains manifest of the tdf.
        /// \param ignoreKeyAccessType - If true skips the key access type before
        /// syncing.
        // ignoreType if true skips the key access type check when syncing
        void upsert(ManifestDataModel& manifestDataModel, bool ignoreKeyAccessType = false) const ;

        /// Unwrap the key from the manifest.
        /// \param manifestDataModel - Data model contains manifest of the tdf.
        /// \return - Wrapped key.
        WrappedKey unwrapKey(ManifestDataModel& manifestDataModel) const;

        /// Parse the response and retrieve the wrapped key.
        /// \param unwrapResponse - The response string from '/rewrap'
        /// \return - Wrapped key.
        WrappedKey getWrappedKey(const std::string& unwrapResponse) const;

        /// Generate a html tdf type file.
        /// \param manifest - Manifest of the tdf file.
        /// \param inputStream - input stream of tdf data.
        /// \param outputProvider - The decrypted data will be write to output provider/
        inline void generateHtmlTdf(const std::string& manifest,
                                    std::istream& inputStream,
                                    IOutputProvider& outputProvider);

        /// Return tdf zip data by parsing html tdf file.
        /// \param htmlTDFFilepath - A tdf file in .html format.
        /// \param manifestData - If true return manifest data otherwise return tdf zip data.
        /// \return - TDF zip data.
        static std::vector<std::uint8_t> getTDFZipData(const std::string& htmlTDFFilepath,
                                                       bool manifestData = false);

        /// Return tdf zip data by parsing html tdf file.
        /// \param bytes - The payload of the html.
        /// \param manifestData - If true return manifest data otherwise return tdf zip data.
        /// \return - TDF zip data.
        static std::vector<std::uint8_t> getTDFZipData(Bytes bytes, bool manifestData = false);

        /// Return tdf zip data from XMLDoc object.
        /// \param xmlDocPtr - The unique ptr of XMLDoc object.
        /// \param manifestData - If true return manifest data otherwise return tdf zip data.
        /// \return - TDF zip data.
        static std::vector<std::uint8_t> getTDFZipData(XMLDocFreePtr xmlDocPtr, bool manifestData);

        /// Return the TDF protocol used to encrypt the input stream data
        /// \param inputProvider - Input provider interface for reading data
        /// \return TDF protocol used to encrypt the input stream data
        static Protocol encryptedWithProtocol(IInputProvider& inputProvider);

        /// Retrive the policy uuid(id) from the manifest data model.
        /// \param manifestDataModel - The manifest data model
        /// \return String - The policy id.
        std::string getPolicyFromManifest(const ManifestDataModel& manifestDataModel) const;

        /// Return the manifest data model from the tdf input provider.
        /// \param inputProvider - Input provider interface for reading data
        /// \return - Return the manifest data model
        ManifestDataModel getManifest(IInputProvider& inputProvider) const;

        /// Retrive the policy uuid(id) from the manifest data model.
        /// \param manifestDataModel - The manifest data model
        /// \return String - The policy id.
        std::string getPolicyIdFromManifest(const ManifestDataModel& manifestDataModel) const;

        /// Validate the supported cipher type
        /// \param manifestDataModel - Manifest data model.
        void validateCipherType(const ManifestDataModel& manifestDataModel) const;

        /// Validate the root signature.
        /// \param splitKey - split key to validate the signature
        /// \param manifestDataModel -TManifest data model.
        void validateRootSignature(SplitKey& splitKey, const ManifestDataModel& manifestDataModel) const;

    private: /// Data

        TDFBuilder& m_tdfBuilder;
    };

} // namespace virtru

#endif // VIRTRU_TDF_IMPL_H