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

#include <memory>
#include <stdint.h>
#include <boost/algorithm/string.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include "logger.h"
#include "nlohmann/json.hpp"
#include "manifest_data_model.h"
#include "tdf_exception.h"

namespace virtru {

    /// Create a manifest data model from json
    /// \param modelAsJsonStr
    /// \return Return a new ManifestDatModel
    ManifestDataModel ManifestDataModel::CreateModelFromJson(const std::string& modelAsJsonStr) {
        ManifestDataModel model;

        try {
            // Parse the manifest
            auto manifest = nlohmann::json::parse(modelAsJsonStr);

            // 'payload'
            model.payload.type = manifest[kPayload][kPayloadReferenceType];
            model.payload.url = manifest[kPayload][kUrl];
            model.payload.protocol = manifest[kPayload][kProtocol];
            model.payload.isEncrypted = manifest[kPayload][kIsEncryptedAttribute];

            if (manifest[kPayload].find(kPayloadMimeType) != manifest[kPayload].end()) {
                model.payload.mimeType = manifest[kPayload][kPayloadMimeType];
            }

            // 'encryptionInformation'
            auto& encryptionInformation = manifest[kEncryptionInformation];
            model.encryptionInformation.keyAccessType = encryptionInformation[kPayloadReferenceType];

            // 'keyAccess'
            auto& keyAccess = encryptionInformation[kKeyAccess];
            for (auto& key : keyAccess) {

                KeyAccessDataModel keyAccessObj;
                keyAccessObj.keyType = key[kKeyAccessType];
                keyAccessObj.url =  key[kUrl];
                keyAccessObj.protocol =  key[kProtocol];

                if (key.find(kWrappedKey) != key.end()) {
                    keyAccessObj.wrappedKey = key[kWrappedKey];
                }

                if (key.find(kPolicyBinding) != key.end()) {
                    keyAccessObj.policyBinding = key[kPolicyBinding];
                }

                if (key.find(kEncryptedMetadata) != key.end()) {
                    keyAccessObj.encryptedMetadata = key[kEncryptedMetadata];
                }

                model.encryptionInformation.keyAccessObjects.emplace_back(keyAccessObj);
            }

            // 'method'
            model.encryptionInformation.method.algorithm =  encryptionInformation[kMethod][kAlgorithm];
            model.encryptionInformation.method.isStreamable =  encryptionInformation[kMethod][kIsStreamable];
            model.encryptionInformation.method.iv =  encryptionInformation[kMethod][kIV];

            // 'integrityInformation'
            auto& integrityInformation = encryptionInformation[kIntegrityInformation];

            model.encryptionInformation.integrityInformation.rootSignature.algorithm = integrityInformation[kRootSignature][kRootSignatureAlg];
            model.encryptionInformation.integrityInformation.rootSignature.signature = integrityInformation[kRootSignature][kRootSignatureSig];
            model.encryptionInformation.integrityInformation.segmentSizeDefault = integrityInformation[kSegmentSizeDefault];
            model.encryptionInformation.integrityInformation.segmentHashAlg = integrityInformation[kSegmentHashAlg];

            // 'segments'
            auto& segments = integrityInformation[kSegments];
            for (auto& segment : segments) {
                SegmentInfoDataModel segmentObj;
                segmentObj.hash = segment[kHash];
                segmentObj.segmentSize = segment[kSegmentSize];
                segmentObj.encryptedSegmentSize = segment[kEncryptedSegmentSize];

                model.encryptionInformation.integrityInformation.segments.emplace_back(segmentObj);
            }

            model.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault = integrityInformation[kEncryptedSegSizeDefault];
            model.encryptionInformation.policy = encryptionInformation[kPolicy];

            return model;
        }  catch (...) {
            LogError("Exception in ManifestDataModel::CreateModelFromJson");
            ThrowException("Could not parse manifest in JSON format: " + boost::current_exception_diagnostic_information(),
                           VIRTRU_TDF_FORMAT_ERROR);
        }
    }

    /// Return the manifest data to json string.
    std::string ManifestDataModel::toJson() const {

        try {
            nlohmann::json manifest;

            // Payload
            nlohmann::json payloadJson;
            payloadJson[kPayloadReferenceType] = payload.type;
            payloadJson[kUrl] = payload.url;
            payloadJson[kProtocol] = payload.protocol;
            payloadJson[kIsEncryptedAttribute] = payload.isEncrypted;
            payloadJson[kPayloadMimeType] = payload.mimeType;

            // EncryptionInformation
            nlohmann::json encryptionInformationJson;
            encryptionInformationJson[kPayloadReferenceType] = encryptionInformation.keyAccessType;

            // 'keyAccess'
            encryptionInformationJson[kKeyAccess] = nlohmann::json::array();
            for (auto& key : encryptionInformation.keyAccessObjects) {

                nlohmann::json keyAccess;
                keyAccess[kKeyAccessType] = key.keyType;
                keyAccess[kUrl] = key.url;
                keyAccess[kProtocol] = key.protocol;
                keyAccess[kWrappedKey] = key.wrappedKey;
                keyAccess[kPolicyBinding] = key.policyBinding;

                if (!key.encryptedMetadata.empty()) {
                    keyAccess[kEncryptedMetadata] = key.encryptedMetadata;
                }

                encryptionInformationJson[kKeyAccess].emplace_back(keyAccess);
            }

            // 'method'
            nlohmann::json method;
            method[kIsStreamable] = encryptionInformation.method.isStreamable;
            method[kIV] = encryptionInformation.method.iv;
            method[kCipherAlgorithm] = encryptionInformation.method.algorithm;
            encryptionInformationJson[kMethod] = method;

            // 'integrityInformation'
            nlohmann::json integrityInformationJson;
            nlohmann::json rootSignatureJson;

            rootSignatureJson[kRootSignatureAlg] = encryptionInformation.integrityInformation.rootSignature.algorithm;
            rootSignatureJson[kRootSignatureSig] = encryptionInformation.integrityInformation.rootSignature.signature;


            integrityInformationJson[kRootSignature] = rootSignatureJson;
            integrityInformationJson[kSegmentSizeDefault] = encryptionInformation.integrityInformation.segmentSizeDefault;
            integrityInformationJson[kSegmentHashAlg] =  encryptionInformation.integrityInformation.segmentHashAlg;
            integrityInformationJson[kEncryptedSegSizeDefault] =  encryptionInformation.integrityInformation.encryptedSegmentSizeDefault;

            integrityInformationJson[kSegments] = nlohmann::json::array();

            // 'segments'
            for (auto& segment : encryptionInformation.integrityInformation.segments) {

                nlohmann::json segmentJson;
                segmentJson[kHash] = segment.hash;

                segmentJson[kSegmentSize] = segment.segmentSize;
                segmentJson[kEncryptedSegmentSize] = segment.encryptedSegmentSize;
                integrityInformationJson[kSegments].emplace_back(segmentJson);
            }

            encryptionInformationJson[kIntegrityInformation] = integrityInformationJson;
            encryptionInformationJson[kPolicy] = encryptionInformation.policy;

            manifest[kEncryptionInformation] = encryptionInformationJson;
            manifest[kPayload] = payloadJson;

            return to_string(manifest);
        }  catch (...) {
            LogError("Exception in ManifestDataModel::CreateModelFromJson");
            ThrowException("Could not parse manifest in JSON format: " + boost::current_exception_diagnostic_information(),
                           VIRTRU_TDF_FORMAT_ERROR);
        }
    }

    /// Return json string representation of key access data model object.
    std::string ManifestDataModel::keyAccessDataModelAsJson(const KeyAccessDataModel& keyAccessDataModel) {

        nlohmann::json keyAccessJson;
        keyAccessJson[kKeyAccessType] = keyAccessDataModel.keyType;
        keyAccessJson[kUrl] = keyAccessDataModel.url;
        keyAccessJson[kProtocol] = keyAccessDataModel.protocol;

        if (!keyAccessDataModel.wrappedKey.empty()) {
            keyAccessJson[kWrappedKey] = keyAccessDataModel.wrappedKey;
        }

        if (!keyAccessDataModel.policyBinding.empty()) {
            keyAccessJson[kPolicyBinding] = keyAccessDataModel.policyBinding;
        }

        if (!keyAccessDataModel.encryptedMetadata.empty()) {
            keyAccessJson[kEncryptedMetadata] = keyAccessDataModel.encryptedMetadata;
        }

        return to_string(keyAccessJson);
    }
}