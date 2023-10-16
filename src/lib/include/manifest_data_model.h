/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
// Created by Sujan Reddy on 3/28/23.
//

#ifndef VIRTRU_MANIFEST_DATA_MODEL_H
#define VIRTRU_MANIFEST_DATA_MODEL_H

#include <string>
#include <vector>
#include "sdk_constants.h"
#include "tdf_assertion.h"

namespace virtru {
    struct SegmentInfoDataModel {
        std::string hash;
        uint32_t segmentSize;
        uint32_t encryptedSegmentSize;
    };

    struct RootSignature {
        std::string algorithm{kRootSignatureAlgDefault};
        std::string signature;
    };

    struct IntegrityInformation {
        RootSignature rootSignature;
        uint32_t segmentSizeDefault;
        std::string segmentHashAlg;
        std::vector<SegmentInfoDataModel> segments;
        uint32_t encryptedSegmentSizeDefault;
    };

    struct KeyAccessDataModel {
        std::string keyType;
        std::string url;
        std::string protocol{kKasProtocol};
        std::string wrappedKey;
        std::string policyBinding;
        std::string encryptedMetadata;
    };

    struct Method {
        std::string algorithm{kCipherAlgorithmGCM};
        bool isStreamable{true};
        std::string iv;
    };

    struct Payload {
        std::string type{kPayloadReference};
        std::string url{kTDFPayloadFileName};
        std::string protocol{kPayloadZipProtcol};
        std::string mimeType {kDefaultMimeType};
        bool isEncrypted{true};
        IntegrityInformation integrityInformation;
    };

    struct EncryptionInformation {
        std::string keyAccessType{kSplitKeyType};
        std::vector<KeyAccessDataModel> keyAccessObjects;
        Method method;
        IntegrityInformation integrityInformation;
        std::string policy;
    };

    class ManifestDataModel {
    public: /// static method
        /// Create a manifest data model from json
        /// \param modelAsJsonStr
        /// \return Return a new ManifestDatModel
        static ManifestDataModel CreateModelFromJson(const std::string& modelAsJsonStr);

        /// Create a manifest data model from xml
        /// \param modelAsXMLStr
        /// \return Return a new ManifestDatModel
        static ManifestDataModel CreateModelFromXML(const std::string& modelAsXMLStr);

        /// Return json string representation of key access data model object.
        /// \param ManifestDataModel - The manifest data model
        /// \return Json string representation of key access data model object.
        static std::string keyAccessDataModelAsJson(const ManifestDataModel& dataModel);

        /// Construct encrypted policy object for ICTDF format
        /// \param ManifestDataModel - The manifest data model
        /// \return Return json string of encrypted policy object representation
        static std::string constructEncryptedPolicyObject(const ManifestDataModel& dataModel);

        /// Update the data model with encrypted policy object information.
        /// \param encryptedPolicyObjectAsJsonStr - Json string of encrypted policy object representation
        /// \param dataModel - The manifest data model
        static void updateDataModelWithEncryptedPolicyObject(const std::string& encryptedPolicyObjectAsJsonStr,
                                                             ManifestDataModel& dataModel);

        /// Return assertion as json string(canonicalization)
        /// \param assertion - The assertion
        /// \return assertion as json string(canonicalization)
        static std::string assertionAsJson(const Assertion& assertion);

    public:
        /// Constructor
        ManifestDataModel() = default;

        /// Destructors
        ~ManifestDataModel()  = default;

        /// Copy constructor
        ManifestDataModel(const ManifestDataModel& dataModel) = default;

        /// Assignment operator
        ManifestDataModel& operator=(const ManifestDataModel& dataModel)  = default;

        /// Move copy constructor
        ManifestDataModel(ManifestDataModel&& dataModel) noexcept  = default;

        /// Move assignment operator
        ManifestDataModel& operator=(ManifestDataModel&& dataModel) noexcept  = default;

        /// Return the manifest data to json string.
        /// \return Manifest data as json string
        std::string toJson() const;

        /// Return the manifest data to XML string.
        /// \return Manifest data as XML string
        std::string toXML() const;

    public:
        /// Data
        Payload payload;
        EncryptionInformation encryptionInformation;
        std::vector<Assertion> assertions;
    };
}

#endif //VIRTRU_MANIFEST_DATA_MODEL_H
