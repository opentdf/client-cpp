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
#include <boost/algorithm/string.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include "logger.h"
#include "nlohmann/json.hpp"
#include "manifest_data_model.h"
#include "crypto_utils.h"
#include "tdf_exception.h"
#include <magic_enum.hpp>

#include <iostream>

namespace virtru {

    using namespace virtru::crypto;

    static constexpr auto kStatementValue = "value";
    static constexpr auto kStatement = "statement";
    static constexpr auto kStatementMetadata = "statementMetadata";
    static constexpr auto kDefaultAssertions = "default";
    static constexpr auto kHandlingAssertions = "handling";
    static constexpr auto kAssertions = "assertions";
    static constexpr auto kXMLBase64Value = "xml-base64";
    static constexpr auto kHandlingStatement = "HandlingStatement";

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

            if (model.payload.isEncrypted) {
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
            } else {
                // 'integrityInformation'
                auto& integrityInformation =  manifest[kPayload][kIntegrityInformation];

                model.payload.integrityInformation.rootSignature.algorithm = integrityInformation[kRootSignature][kRootSignatureAlg];
                model.payload.integrityInformation.rootSignature.signature = integrityInformation[kRootSignature][kRootSignatureSig];
                model.payload.integrityInformation.segmentSizeDefault = integrityInformation[kSegmentSizeDefault];
                model.payload.integrityInformation.segmentHashAlg = integrityInformation[kSegmentHashAlg];

                // 'segments'
                auto& segments = integrityInformation[kSegments];
                for (auto& segment : segments) {
                    SegmentInfoDataModel segmentObj;
                    segmentObj.hash = segment[kHash];
                    segmentObj.segmentSize = segment[kSegmentSize];
                    segmentObj.encryptedSegmentSize = segment[kEncryptedSegmentSize];

                    model.payload.integrityInformation.segments.emplace_back(segmentObj);
                }

                model.payload.integrityInformation.encryptedSegmentSizeDefault = integrityInformation[kEncryptedSegSizeDefault];
            }

            // 'assertions'
            if (manifest.find(kAssertions) != manifest.end()) {
                const auto& assertions = manifest[kAssertions];

                for (const auto& assertion: assertions) {

                    std::string assertionType = assertion[kAssertionType];

                    // 'default' assertions
                    if (boost::iequals(assertionType, magic_enum::enum_name(AssertionType::Base))) {

                        Assertion defaultAssertion{AssertionType::Base, Scope::Unknown};

                        std::string scopeValue = assertion[kScopeAttribute];
                        auto scope = magic_enum::enum_cast<Scope>(scopeValue);
                        if (scope.has_value()) {
                            defaultAssertion.setScope(scope.value());
                        }
                        defaultAssertion.getId() = assertion[kIdAttribute];


                        const auto& statementGroupJson = assertion[kStatement];

                        auto statementGroup = defaultAssertion.getStatementGroup();

                        std::string typeAsStr = statementGroupJson[kTypeAttribute];
                        auto type = magic_enum::enum_cast<StatementType>(typeAsStr);
                        if (type.has_value()) {
                            statementGroup.setStatementType(type.value());
                        }

                        if (statementGroupJson.find(kFilenameAttribute) != statementGroupJson.end()) {
                            statementGroup.setFilename(statementGroupJson[kFilenameAttribute]);
                        }

                        if (statementGroupJson.find(kMediaTypeAttribute) != statementGroupJson.end()) {
                            statementGroup.setMediaType(statementGroupJson[kMediaTypeAttribute]);
                        }

                        if (statementGroupJson.find(kUriAttribute) != statementGroupJson.end()) {
                            statementGroup.setUri(statementGroupJson[kUriAttribute]);
                        }

                        if (statementGroupJson.find(kStatementValue) != statementGroupJson.end()) {
                            statementGroup.setValue(statementGroupJson[kStatementValue]);
                        }

                        if (statementGroupJson.find(kIsEncryptedAttribute) != statementGroupJson.end()) {
                            statementGroup.setIsEncrypted(statementGroupJson[kIsEncryptedAttribute]);
                        }

                        defaultAssertion.setStatementGroup(statementGroup);

                        for (const auto& metadata: assertion[kStatementMetadata]) {
                            defaultAssertion.setStatementMetadata(to_string(metadata));
                        }

                        model.assertions.emplace_back(defaultAssertion);


                    } else if (boost::iequals(assertionType, magic_enum::enum_name(AssertionType::Handling))) { // 'handling' assertions

                        Assertion handlingAssertion{AssertionType::Handling, Scope::Unknown};

                        std::string scopeValue = assertion[kScopeAttribute];
                        auto scope = magic_enum::enum_cast<Scope>(scopeValue);
                        if (scope.has_value()) {
                            handlingAssertion.setScope(scope.value());
                        }

                        std::string appliesToStateValue = assertion[kAppliesToStateAttribute];
                        auto appliesToState = magic_enum::enum_cast<AppliesToState>(appliesToStateValue);
                        if (appliesToState.has_value()) {
                            handlingAssertion.setAppliesToState(appliesToState.value());
                        }

                        if (assertion.find(kIdAttribute) != assertion.end()) {
                            handlingAssertion.setId(assertion[kIdAttribute]);
                        }

                        if (assertion.find(kAssertionHash) != assertion.end()) {
                            handlingAssertion.setAssertionHash(assertion[kAssertionHash]);
                        }

                        if (assertion.find(kAssertionSignature) != assertion.end()) {
                            handlingAssertion.setAssertionSignature(assertion[kAssertionSignature]);
                        }

                        const auto& statementGroupJson = assertion[kStatement];

                        auto statementGroup = handlingAssertion.getStatementGroup();
                        std::string typeAsStr = statementGroupJson[kTypeAttribute];

                        auto type = magic_enum::enum_cast<StatementType>(typeAsStr);
                        if (type.has_value()) {
                            statementGroup.setStatementType(type.value());
                        }

                        if (statementGroupJson.find(kStatementValue) != statementGroupJson.end()) {
                            std::string value = statementGroupJson[kStatementValue];
                            statementGroup.setValue(base64Decode(value));
                        }

                        handlingAssertion.setStatementGroup(statementGroup);
                        model.assertions.emplace_back(handlingAssertion);

                    }
                }
            }

            return model;
        }  catch (...) {
            LogError("Exception in ManifestDataModel::CreateModelFromJson");
            ThrowException("Could not parse manifest in JSON format: " + boost::current_exception_diagnostic_information(),
                           VIRTRU_TDF_FORMAT_ERROR);
        }

        return model;
    }

    /// Return the manifest data to json string.
    std::string ManifestDataModel::toJson() const {

        nlohmann::json manifest{};

        try {
            // Payload
            nlohmann::json payloadJson;
            payloadJson[kPayloadReferenceType] = payload.type;
            payloadJson[kUrl] = payload.url;
            payloadJson[kProtocol] = payload.protocol;
            payloadJson[kIsEncryptedAttribute] = payload.isEncrypted;
            payloadJson[kPayloadMimeType] = payload.mimeType;

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

            if (payload.isEncrypted) {
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
                encryptionInformationJson[kIntegrityInformation] = integrityInformationJson;

                // 'method'
                nlohmann::json method;
                method[kIsStreamable] = encryptionInformation.method.isStreamable;
                method[kIV] = encryptionInformation.method.iv;
                method[kCipherAlgorithm] = encryptionInformation.method.algorithm;
                encryptionInformationJson[kMethod] = method;
                encryptionInformationJson[kPolicy] = encryptionInformation.policy;

                manifest[kEncryptionInformation] = encryptionInformationJson;
                manifest[kPayload] = payloadJson;
            } else {
                payloadJson[kIntegrityInformation] = integrityInformationJson;
                manifest[kPayload] = payloadJson;
            }

            //  assertions array
            auto assertionsJsonArray = nlohmann::json::array();
            for (const auto& assertion: assertions) {

                if (assertion.getAssertionType() == AssertionType::Base) {

                    nlohmann::json assertionJson;

                    assertionJson[kAssertionType] =  magic_enum::enum_name(AssertionType::Base);

                    if (assertion.getScope() != Scope::Unknown) {
                        assertionJson[kScopeAttribute] = magic_enum::enum_name(assertion.getScope());
                    }

                    if (!assertion.getId().empty()) {
                        assertionJson[kIdAttribute] = assertion.getId();
                    }

                    if (!assertion.getType().empty()) {
                        assertionJson[kTypeAttribute] = assertion.getType();
                    }

                    auto statementGroup = assertion.getStatementGroup();
                    if (statementGroup.getStatementType() != StatementType::Unknown) {
                        nlohmann::json statementGroupJson;

                        statementGroupJson[kTypeAttribute] =  magic_enum::enum_name(statementGroup.getStatementType());

                        if (!statementGroup.getFilename().empty()) {
                            statementGroupJson[kFilenameAttribute] =  statementGroup.getFilename();
                        }

                        if (!statementGroup.getMediaType().empty()) {
                            statementGroupJson[kMediaTypeAttribute] =  statementGroup.getMediaType();
                        }

                        if (!statementGroup.getUri().empty()) {
                            statementGroupJson[kUriAttribute] =  statementGroup.getUri();
                        }

                        if (!statementGroup.getValue().empty()) {
                            statementGroupJson[kStatementValue] =  statementGroup.getValue();
                        }

                        statementGroupJson[kIsEncryptedAttribute] = statementGroup.getIsEncrypted();
                        assertionJson[kStatement] = statementGroupJson;
                    }

                    auto statementMetaDataJsonArray = nlohmann::json::array();
                    for (const auto& metaData: assertion.getStatementMetadata()) {
                        statementMetaDataJsonArray.emplace_back(metaData);
                    }
                    assertionJson[kStatementMetadata] = statementMetaDataJsonArray;
                    assertionJson[kEncryptionInformationElement] = nlohmann::json::object();

                    assertionsJsonArray.emplace_back(assertionJson);
                } else if (assertion.getAssertionType() == AssertionType::Handling) {

                    nlohmann::json assertionJson;

                    assertionJson[kAssertionType] =  magic_enum::enum_name(AssertionType::Handling);

                    auto scope = assertion.getScope();
                    if (scope != Scope::Unknown) {
                        assertionJson[kScopeAttribute] = magic_enum::enum_name(scope);
                    }

                    auto appliedState = assertion.getAppliesToState();
                    if (appliedState != AppliesToState::Unknown) {
                        assertionJson[kAppliesToStateAttribute] = magic_enum::enum_name(appliedState);
                    }

                    auto id = assertion.getId();
                    if (!id.empty()) {
                        assertionJson[kIdAttribute] = id;
                    }

                    auto assertionHash = assertion.getAssertionHash();
                    if (!assertionHash.empty()) {
                        assertionJson[kAssertionHash] = assertionHash;
                    }

                    auto assertionSignature = assertion.getAssertionSignature();
                    if (!assertionSignature.empty()) {
                        assertionJson[kAssertionSignature] = assertionSignature;
                    }

                    auto statementGroup = assertion.getStatementGroup();
                    if (statementGroup.getStatementType() != StatementType::Unknown) {
                        nlohmann::json statementGroupJson;

                        statementGroupJson[kTypeAttribute] =  magic_enum::enum_name(statementGroup.getStatementType());
                        statementGroupJson[kStatementValue] = base64Encode(statementGroup.getValue());

                        assertionJson[kStatement] = statementGroupJson;
                    }

                    assertionJson[kEncryptionInformationElement] = nlohmann::json::object();
                    assertionsJsonArray.emplace_back(assertionJson);
                }
            }

            manifest[kAssertions] = assertionsJsonArray;

            return to_string(manifest);
        }  catch (...) {
            LogError("Exception in ManifestDataModel::CreateModelFromJson");
            ThrowException("Could not parse manifest in JSON format: " + boost::current_exception_diagnostic_information(),
                           VIRTRU_TDF_FORMAT_ERROR);
        }

        return to_string(manifest);
    }

    /// Return json string representation of key access data model object.
    std::string ManifestDataModel::keyAccessDataModelAsJson(const ManifestDataModel& dataModel) {

        nlohmann::json keyAccessObjs;

        // 'keyAccess'
        keyAccessObjs[kKeyAccess] = nlohmann::json::array();
        for (auto& key : dataModel.encryptionInformation.keyAccessObjects) {

            nlohmann::json keyAccess;
            keyAccess[kKeyAccessType] = key.keyType;
            keyAccess[kUrl] = key.url;
            keyAccess[kProtocol] = key.protocol;
            keyAccess[kWrappedKey] = key.wrappedKey;
            keyAccess[kPolicyBinding] = key.policyBinding;

            if (!key.encryptedMetadata.empty()) {
                keyAccess[kEncryptedMetadata] = key.encryptedMetadata;
            }

            keyAccessObjs[kKeyAccess].emplace_back(keyAccess);
        }

        return to_string(keyAccessObjs);
    }

    /// Construct encrypted policy object for ICTDF format
    std::string ManifestDataModel::constructEncryptedPolicyObject(const ManifestDataModel& dataModel) {

        try {
            nlohmann::json encryptedPolicyObject;

            // 'keyAccess'
            encryptedPolicyObject[kKeyAccess] = nlohmann::json::array();
            for (auto& key : dataModel.encryptionInformation.keyAccessObjects) {

                nlohmann::json keyAccess;
                keyAccess[kKeyAccessType] = key.keyType;
                keyAccess[kUrl] = key.url;
                keyAccess[kProtocol] = key.protocol;
                keyAccess[kWrappedKey] = key.wrappedKey;
                keyAccess[kPolicyBinding] = key.policyBinding;

                if (!key.encryptedMetadata.empty()) {
                    keyAccess[kEncryptedMetadata] = key.encryptedMetadata;
                }

                encryptedPolicyObject[kKeyAccess].emplace_back(keyAccess);
            }

            // 'integrityInformation'
            nlohmann::json integrityInformationJson;
            nlohmann::json rootSignatureJson;

            rootSignatureJson[kRootSignatureAlg] = dataModel.encryptionInformation.integrityInformation.rootSignature.algorithm;
            rootSignatureJson[kRootSignatureSig] = dataModel.encryptionInformation.integrityInformation.rootSignature.signature;


            integrityInformationJson[kRootSignature] = rootSignatureJson;
            integrityInformationJson[kSegmentSizeDefault] = dataModel.encryptionInformation.integrityInformation.segmentSizeDefault;
            integrityInformationJson[kSegmentHashAlg] =  dataModel.encryptionInformation.integrityInformation.segmentHashAlg;
            integrityInformationJson[kEncryptedSegSizeDefault] =  dataModel.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault;

            integrityInformationJson[kSegments] = nlohmann::json::array();

            // 'segments'
            for (auto& segment : dataModel.encryptionInformation.integrityInformation.segments) {

                nlohmann::json segmentJson;
                segmentJson[kHash] = segment.hash;

                segmentJson[kSegmentSize] = segment.segmentSize;
                segmentJson[kEncryptedSegmentSize] = segment.encryptedSegmentSize;
                integrityInformationJson[kSegments].emplace_back(segmentJson);
            }

            encryptedPolicyObject[kIntegrityInformation] = integrityInformationJson;
            encryptedPolicyObject[kPolicy] = dataModel.encryptionInformation.policy;

            return to_string(encryptedPolicyObject);
        }  catch (...) {
            LogError("Exception in ManifestDataModel::constructEncryptedPolicyObject");
            ThrowException("Could not parse manifest in JSON format: " + boost::current_exception_diagnostic_information(),
                           VIRTRU_TDF_FORMAT_ERROR);
        }

    }


    /// Update the data model with encrypted policy object information.
    void ManifestDataModel::updateDataModelWithEncryptedPolicyObject(const std::string& encryptedPolicyObjectAsJsonStr,
                                                                     ManifestDataModel& dataModel) {

        try {
            // Parse the manifest
            auto encryptedPolicyObject = nlohmann::json::parse(encryptedPolicyObjectAsJsonStr);

            // 'keyAccess'
            auto& keyAccess = encryptedPolicyObject[kKeyAccess];
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

                dataModel.encryptionInformation.keyAccessObjects.emplace_back(keyAccessObj);
            }

            // 'integrityInformation'
            auto& integrityInformation = encryptedPolicyObject[kIntegrityInformation];

            dataModel.encryptionInformation.integrityInformation.rootSignature.algorithm = integrityInformation[kRootSignature][kRootSignatureAlg];
            dataModel.encryptionInformation.integrityInformation.rootSignature.signature = integrityInformation[kRootSignature][kRootSignatureSig];
            dataModel.encryptionInformation.integrityInformation.segmentSizeDefault = integrityInformation[kSegmentSizeDefault];
            dataModel.encryptionInformation.integrityInformation.segmentHashAlg = integrityInformation[kSegmentHashAlg];

            // 'segments'
            auto& segments = integrityInformation[kSegments];
            for (auto& segment : segments) {
                SegmentInfoDataModel segmentObj;
                segmentObj.hash = segment[kHash];
                segmentObj.segmentSize = segment[kSegmentSize];
                segmentObj.encryptedSegmentSize = segment[kEncryptedSegmentSize];

                dataModel.encryptionInformation.integrityInformation.segments.emplace_back(segmentObj);
            }

            dataModel.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault = integrityInformation[kEncryptedSegSizeDefault];
            dataModel.encryptionInformation.policy = encryptedPolicyObject[kPolicy];
        }  catch (...) {
            LogError("Exception in ManifestDataModel::updateDataModelWithEncryptedPolicyObject");
            ThrowException("Could not parse manifest in JSON format: " + boost::current_exception_diagnostic_information(),
                           VIRTRU_TDF_FORMAT_ERROR);
        }
    }

    /// Return assertion as json string(canonicalization)
    std::string ManifestDataModel::assertionAsJson(const Assertion &assertion) {
        nlohmann::ordered_json assertionJson;

        if (assertion.getAssertionType() == AssertionType::Base) {

            assertionJson[kAssertionType] = magic_enum::enum_name(AssertionType::Base);

            if (assertion.getScope() != Scope::Unknown) {
                assertionJson[kScopeAttribute] = magic_enum::enum_name(assertion.getScope());
            }

            if (!assertion.getId().empty()) {
                assertionJson[kIdAttribute] = assertion.getId();
            }

            if (!assertion.getType().empty()) {
                assertionJson[kTypeAttribute] = assertion.getType();
            }

            auto statementGroup = assertion.getStatementGroup();
            if (statementGroup.getStatementType() != StatementType::Unknown) {
                nlohmann::json statementGroupJson;

                statementGroupJson[kTypeAttribute] = magic_enum::enum_name(statementGroup.getStatementType());

                if (!statementGroup.getFilename().empty()) {
                    statementGroupJson[kFilenameAttribute] = statementGroup.getFilename();
                }

                if (!statementGroup.getMediaType().empty()) {
                    statementGroupJson[kMediaTypeAttribute] = statementGroup.getMediaType();
                }

                if (!statementGroup.getUri().empty()) {
                    statementGroupJson[kUriAttribute] = statementGroup.getUri();
                }

                if (!statementGroup.getValue().empty()) {
                    statementGroupJson[kStatementValue] = statementGroup.getValue();
                }

                statementGroupJson[kIsEncryptedAttribute] = statementGroup.getIsEncrypted();
                assertionJson[kStatement] = statementGroupJson;
            }

            auto statementMetaDataJsonArray = nlohmann::json::array();
            for (const auto &metaData: assertion.getStatementMetadata()) {
                statementMetaDataJsonArray.emplace_back(metaData);
            }
            assertionJson[kStatementMetadata] = statementMetaDataJsonArray;
            assertionJson[kEncryptionInformationElement] = nlohmann::json::object();

        } else if (assertion.getAssertionType() == AssertionType::Handling) {

            auto appliedState = assertion.getAppliesToState();
            if (appliedState != AppliesToState::Unknown) {
                assertionJson[kAppliesToStateAttribute] = magic_enum::enum_name(appliedState);
            }

            auto assertionHash = assertion.getAssertionHash();
            if (!assertionHash.empty()) {
                assertionJson[kAssertionHash] = assertionHash;
            }

            auto assertionSignature = assertion.getAssertionSignature();
            if (!assertionSignature.empty()) {
                assertionJson[kAssertionSignature] = assertionSignature;
            }

            assertionJson[kEncryptionInformationElement] = nlohmann::json::object();

            auto id = assertion.getId();
            if (!id.empty()) {
                assertionJson[kIdAttribute] = id;
            }

            auto statementGroup = assertion.getStatementGroup();
            if (statementGroup.getStatementType() != StatementType::Unknown) {
                nlohmann::json statementGroupJson;

                statementGroupJson[kTypeAttribute] = magic_enum::enum_name(statementGroup.getStatementType());
                statementGroupJson[kStatementValue] = base64Encode(statementGroup.getValue());

                assertionJson[kStatement] = statementGroupJson;
            }

            auto scope = assertion.getScope();
            if (scope != Scope::Unknown) {
                assertionJson[kScopeAttribute] = magic_enum::enum_name(scope);
            }

            assertionJson[kAssertionType] = magic_enum::enum_name(AssertionType::Handling);

        }

        return assertionJson.dump();
    }
}
